using FxSsh.Logging;
using FxSsh.Services;
using FxSsh.Services.Sftp;
using FxSsh.SshServerModule.Security;
using FxSsh.SshServerModule.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.Net;
using SshServerModule.Sftp;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FxSsh.SshServerModule
{
    public class HostedServer : IHostedService
    {
        /// <summary>
        /// Interval of the server keepalive probe (keepalive@openssh.com) when no idle timeout is set.
        /// After three unanswered probes the session is closed, so a dead client is removed after about
        /// four minutes.
        /// </summary>
        internal static readonly TimeSpan KeepaliveInterval = TimeSpan.FromSeconds(60);

        /// <summary>One server for each address in <c>ServerSettings.BindToAddress</c> (one dual-stack server by default).</summary>
        private readonly List<SshServer> servers = new();

        private readonly ILogger _logger;
        private readonly IFileSystemFactory _fileSystemFactory;
        public readonly ISettingsRepository _settingsRepository; // public so that we can access it from Blazor page to edit settings
        private readonly LoginBanTracker _bans;
        private readonly IpFilter _ipFilter;
        private readonly SshServerOptions _options;

        /// <param name="options">Port and bind addresses from the configuration; they override the stored settings. Null: stored settings only.</param>
        /// <param name="banTracker">The auto-ban state, shared with the admin UI (AddSshServerSecurity). Null: a private one.</param>
        public HostedServer(ILogger<HostedServer> logger, IFileSystemFactory fileSystemFactory, ISettingsRepository settingsRepository,
            LoginBanTracker banTracker = null, IOptions<SshServerOptions> options = null)
        {
            _options = options?.Value;
            _logger = logger;
            _settingsRepository = settingsRepository;
            _fileSystemFactory = fileSystemFactory;
            _bans = banTracker ?? new LoginBanTracker(TimeProvider.System);
            _ipFilter = new IpFilter(logger);
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            FxSshLogSink.Configure(_logger);

            var settings = _settingsRepository.ServerSettings;
            var banner = string.IsNullOrWhiteSpace(settings.ServerBanner) ? "SSH-2.0-FreeSftpSharp" : settings.ServerBanner;
            if (!banner.StartsWith("SSH-2.0-", StringComparison.Ordinal))
                banner = "SSH-2.0-" + banner; // RFC 4253 section 4.2: the identification string must start with SSH-2.0-

            var listen = EffectiveListenSettings.Resolve(settings, _options);
            _logger.LogInformation("Listen port {Port} (from {PortSource}), bind addresses {BindToAddress} (from {BindSource}).",
                listen.Port, listen.PortSource, listen.BindToAddress.Count == 0 ? "all" : string.Join(", ", listen.BindToAddress), listen.BindSource);

            var timeouts = SessionTimeouts.FromSettings(settings);
            var hostKeys = HostKeys.Load(_settingsRepository);

            try
            {
                foreach (var address in ListenAddresses.Resolve(listen.BindToAddress, _logger))
                {
                    var server = new SshServer(new StartingInfo(address, listen.Port, banner));
                    server.InactivityTimeout = timeouts.InactivityTimeout;
                    foreach (var hostKey in hostKeys)
                        server.AddHostKey(hostKey.Algorithm, hostKey.Pem);
                    server.ConnectionAccepted += OnConnectionAccepted;
                    servers.Add(server);
                    await server.StartAsync(cancellationToken);
                    _logger.LogInformation("Listening on {Address} port {Port}.", address, listen.Port);
                }
            }
            catch
            {
                await StopServersAsync(); // do not keep a part of the listeners open
                throw;
            }
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            await StopServersAsync();
            _settingsRepository.Dispose();
        }

        private async Task StopServersAsync()
        {
            foreach (var server in servers)
            {
                server.ConnectionAccepted -= OnConnectionAccepted;
                await server.StopAsync();
                server.Dispose();
            }
            servers.Clear();
        }

        void OnConnectionAccepted(object sender, Session e)
        {
            var filter = _ipFilter.Check(e.RemoteEndPoint, _settingsRepository.ServerSettings, _bans);
            if (filter != IpFilterResult.Allowed)
            {
                _logger.LogWarning("Refused the connection from {RemoteEndPoint}: {Reason}.", e.RemoteEndPoint, filter);
                // FxSsh has no "reject" hook. An exception from ConnectionAccepted makes SshServer close the socket
                // before the session starts: the client gets no identification line and no key exchange.
                throw new SshConnectionException($"Connection refused: {filter}.", DisconnectReason.HostNotAllowedToConnect);
            }

            _logger.LogInformation("Accepted a client from {RemoteEndPoint}.", e.RemoteEndPoint);

            var timeouts = SessionTimeouts.FromSettings(_settingsRepository.ServerSettings);
            if (timeouts.KeepaliveInterval is { } keepalive)
                e.ConfigureKeepalive(keepalive);

            e.ServiceRegistered += OnServiceRegistered;
        }

        void OnServiceRegistered(object sender, SshService e)
        {
            var session = (Session)sender;
            _logger.LogDebug("Session {RemoteEndPoint} requesting {Service}.", session.RemoteEndPoint, e.GetType().Name);

            if (e is UserAuthService authService)
            {
                var attempt = new AuthAttempt();
                authService.UserAuth += (s, args) => OnUserAuth(args, attempt);
                authService.Succeed += (s, serviceName) => OnUserAuthSucceeded(session, attempt);
            }
            else if (e is ConnectionService connectionService)
            {
                connectionService.SubsystemRequested += OnSubsystemRequested;

                if (_settingsRepository.ServerSettings.EnableCommand)
                    connectionService.CommandOpened += OnServiceCommandOpened;
                if (_settingsRepository.ServerSettings.EnableDirectTcpIp)
                    connectionService.TcpForwardRequest += OnDirectTcpIpReceived;
            }
        }

        void OnDirectTcpIpReceived(object sender, TcpRequestArgs e)
        {
            _logger.LogInformation("Received a request to forward data to {Host}:{Port}", e.Host, e.Port);

            var tcp = new TcpForwardService(e.Host, e.Port, e.OriginatorIP, e.OriginatorPort);
            e.Channel.DataReceived += (ss, ee) => tcp.OnData(ee.ToArray());
            e.Channel.CloseReceived += (ss, ee) => tcp.OnClose();
            // TcpForwardService reuses its receive buffer, so send a copy.
            tcp.DataReceived += (ss, ee) => e.Channel.SendData((byte[])ee.Clone());
            tcp.CloseReceived += (ss, ee) => e.Channel.SendClose();
            tcp.Start();
        }

        /// <summary>The user that the last accepted authentication request of a session was for.</summary>
        private sealed class AuthAttempt
        {
            public volatile string AcceptedUsername;
        }

        void OnUserAuth(UserAuthArgs e, AuthAttempt attempt)
        {
            e.Result = false;
            attempt.AcceptedUsername = null;
            Authenticate(e);

            if (e.Result)
                attempt.AcceptedUsername = e.Username;
            else if (e.AuthMethod == "password")
                RecordFailedLogin(e.Session);
            // Failed public keys are not counted: clients offer each key of their agent, so a user with several keys
            // would be banned. A wrong public key cannot be guessed like a password.
        }

        void Authenticate(UserAuthArgs e)
        {
            if (e.Session.RemoteEndPoint is IPEndPoint remote && _bans.IsBanned(remote.Address))
            {
                // Banned while this session was open: no more attempts on it.
                _logger.LogInformation("Authentication ({Method}) of {Username} refused: {RemoteEndPoint} is banned.",
                    e.AuthMethod, e.Username, e.Session.RemoteEndPoint);
                return;
            }

            var user = e.Username == null ? null : _settingsRepository.GetUser(e.Username);
            if (user == null)
            {
                if (e.AuthMethod == "password")
                    UserLogics.SimulatePasswordCheck(); // same time as for a real user
                _logger.LogInformation("Authentication ({Method}) failed for unknown user {Username} from {RemoteEndPoint}.",
                    e.AuthMethod, e.Username, e.Session.RemoteEndPoint);
                return;
            }

            if (!UserLogics.VerifyUserIpWhitelisted(user, e.Session.RemoteEndPoint))
            {
                _logger.LogInformation("Client {RemoteEndPoint} is not in the IP whitelist of user {Username}.",
                    e.Session.RemoteEndPoint, e.Username);
                return;
            }

            switch (e.AuthMethod)
            {
                case "publickey":
                    e.Result = UserLogics.VerifyUserKey(user, e.Fingerprint);
                    _logger.LogInformation("Public key authentication of {Username}, {KeyAlgorithm} SHA256:{Fingerprint}. Successful: {Result}",
                        e.Username, e.KeyAlgorithm, e.Fingerprint, e.Result);
                    break;
                case "password":
                    e.Result = UserLogics.VerifyUserPassword(user, e.Password, _settingsRepository, _logger);
                    _logger.LogInformation("Password authentication of {Username}. Successful: {Result}", e.Username, e.Result);
                    break;
                default:
                    _logger.LogInformation("Authentication method {Method} is not supported (user {Username}).", e.AuthMethod, e.Username);
                    break;
            }
        }

        void RecordFailedLogin(Session session)
        {
            if (session.RemoteEndPoint is not IPEndPoint remote)
                return;

            var settings = _settingsRepository.ServerSettings;
            if (_bans.RecordFailure(remote.Address, BanPolicy.FromSettings(settings)))
                _logger.LogWarning("Banned {Address} for {Seconds} s after {Failures} failed logins within {Window} s.",
                    CidrNotation.Normalize(remote.Address), settings.BanDurationSeconds, settings.MaxLoginAttemptsBeforeBan,
                    settings.LoginFailureWindowSeconds);
        }

        /// <summary>Called after the whole authentication succeeded (for a public key: after the signature check).</summary>
        void OnUserAuthSucceeded(Session session, AuthAttempt attempt)
        {
            var username = attempt.AcceptedUsername;
            if (username == null)
                return;

            try
            {
                var user = _settingsRepository.GetUser(username);
                if (user == null)
                    return;
                user.LastSuccessfulLogin = _bans.Time.GetUtcNow().UtcDateTime;
                if (!_settingsRepository.UpdateUser(user))
                    _logger.LogWarning("Could not save the last login time of user {Username}.", username);
            }
            catch (Exception ex)
            {
                // The login itself is fine; only the time stamp is lost.
                _logger.LogWarning(ex, "Could not save the last login time of user {Username} from {RemoteEndPoint}.",
                    username, session.RemoteEndPoint);
            }
        }

        void OnSubsystemRequested(object sender, SubsystemRequestedArgs e)
        {
            _logger.LogInformation("Channel {ChannelId} requested subsystem \"{Name}\".", e.Channel.ServerChannelId, e.Name);

            if (e.Name != "sftp" || !e.AttachedUserAuthArgs.Result)
                return; // Agreed stays false: the server answers SSH_MSG_CHANNEL_FAILURE

            var username = e.AttachedUserAuthArgs.Username;
            var user = _settingsRepository.GetUser(username);
            if (user == null)
                return;

            var fileSystem = new SftpFileSystemAdapter(_fileSystemFactory.GetFileSystem(username), _logger, user.Username);
            new SftpService(fileSystem).Attach(e.Channel);
            e.Agreed = true;
        }

        /// <summary>
        /// Shell and exec requests. Running commands is not implemented; when EnableCommand is set, the
        /// server only echoes the command and closes the channel.
        /// </summary>
        void OnServiceCommandOpened(object sender, CommandRequestedArgs e)
        {
            if (!e.AttachedUserAuthArgs.Result || e.ShellType == "subsystem")
                return; // subsystems are handled in OnSubsystemRequested

            _logger.LogInformation("Channel {ChannelId} runs {ShellType}.", e.Channel.ServerChannelId, e.ShellType);

            e.Agreed = true;
            e.Channel.SendData(Encoding.UTF8.GetBytes($"You ran {e.CommandText}\n"));
            e.Channel.SendClose(0);
        }
    }
}
