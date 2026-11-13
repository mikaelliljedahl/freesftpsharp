using FxSsh.Logging;
using FxSsh.Services;
using FxSsh.SshServerModule.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServerModule.Services;
using System;
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

        private SshServer server;

        private readonly ILogger _logger;
        private readonly IFileSystemFactory _fileSystemFactory;
        public readonly ISettingsRepository _settingsRepository; // public so that we can access it from Blazor page to edit settings

        public HostedServer(ILogger<HostedServer> logger, IFileSystemFactory fileSystemFactory, ISettingsRepository settingsRepository)
        {
            _logger = logger;
            _settingsRepository = settingsRepository;
            _fileSystemFactory = fileSystemFactory;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            FxSshLogSink.Configure(_logger);

            var settings = _settingsRepository.ServerSettings;
            var banner = string.IsNullOrWhiteSpace(settings.ServerBanner) ? "SSH-2.0-FreeSftpSharp" : settings.ServerBanner;
            if (!banner.StartsWith("SSH-2.0-", StringComparison.Ordinal))
                banner = "SSH-2.0-" + banner; // RFC 4253 section 4.2: the identification string must start with SSH-2.0-

            server = new SshServer(new StartingInfo(IPAddress.IPv6Any, settings.ListenToPort, banner));

            var timeouts = SessionTimeouts.FromSettings(settings);
            server.InactivityTimeout = timeouts.InactivityTimeout;

            foreach (var hostKey in HostKeys.Load(_settingsRepository))
                server.AddHostKey(hostKey.Algorithm, hostKey.Pem);

            server.ConnectionAccepted += OnConnectionAccepted;
            await server.StartAsync(cancellationToken);
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            if (server != null)
            {
                server.ConnectionAccepted -= OnConnectionAccepted;
                await server.StopAsync();
                server.Dispose();
                server = null;
            }
            _settingsRepository.Dispose();
        }

        void OnConnectionAccepted(object sender, Session e)
        {
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
                authService.UserAuth += OnUserAuth;
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

        void OnUserAuth(object sender, UserAuthArgs e)
        {
            e.Result = false;

            var user = e.Username == null ? null : _settingsRepository.GetUser(e.Username);
            if (user == null)
            {
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
                    e.Result = UserLogics.VerifyUserPassword(user, e.Password);
                    _logger.LogInformation("Password authentication of {Username}. Successful: {Result}", e.Username, e.Result);
                    break;
                default:
                    _logger.LogInformation("Authentication method {Method} is not supported (user {Username}).", e.AuthMethod, e.Username);
                    break;
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

            var sftp = new SftpSubsystem(_logger, _fileSystemFactory.GetFileSystem(username), user.Username);
            SftpChannelBridge.Attach(e.AttachedUserAuthArgs.Session, e.Channel, sftp, _logger);
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

            _logger.LogInformation("Channel {ChannelId} runs {ShellType}: \"{CommandText}\".", e.Channel.ServerChannelId, e.ShellType, e.CommandText);

            e.Agreed = true;
            e.Channel.SendData(Encoding.UTF8.GetBytes($"You ran {e.CommandText}\n"));
            e.Channel.SendClose(0);
        }
    }
}
