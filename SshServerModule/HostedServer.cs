using FxSsh.Logging;
using FxSsh.Messages.UserAuth;
using FxSsh.Services;
using FxSsh.Services.Sftp;
using FxSsh.SshServerModule.Security;
using FxSsh.SshServerModule.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.Connections;
using SshServerModule.Connections;
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
        private readonly IConnectionRegistry _connections;
        private readonly IEventBus _events;

        /// <summary>The protocol name of the auth events.</summary>
        internal const string SshProtocol = "SSH";

        /// <param name="options">Port and bind addresses from the configuration; they override the stored settings. Null: stored settings only.</param>
        /// <param name="banTracker">The auto-ban state, shared with the admin UI (AddSshServerSecurity). Null: a private one.</param>
        /// <param name="connections">The open connections, shared with the admin UI (AddSshServerConnections). Null: a private registry.</param>
        /// <param name="events">The event bus for the auth and system events (AddSshServerEvents). Null: no events.</param>
        public HostedServer(ILogger<HostedServer> logger, IFileSystemFactory fileSystemFactory, ISettingsRepository settingsRepository,
            LoginBanTracker banTracker = null, IOptions<SshServerOptions> options = null, IConnectionRegistry connections = null,
            IEventBus events = null)
        {
            _connections = connections ?? new ConnectionRegistry(TimeProvider.System);
            _options = options?.Value;
            _events = events;
            _logger = logger;
            _settingsRepository = settingsRepository;
            _fileSystemFactory = fileSystemFactory;
            _bans = banTracker ?? new LoginBanTracker(TimeProvider.System);
            _ipFilter = new IpFilter(logger);
        }

        /// <summary>True while the SSH listeners are bound (after a successful start, until the stop). For the readiness check.</summary>
        public bool IsListening { get; private set; }

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
                    Ed25519PublicKey.Register(server); // ed25519 user keys (issue #58)
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

            IsListening = true;
            Publish(new SystemEvent(SystemEventType.Started) { Timestamp = Now, Source = SshProtocol,
                Message = $"Listening on port {listen.Port}." });
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            IsListening = false;
            Publish(new SystemEvent(SystemEventType.Stopping) { Timestamp = Now, Source = SshProtocol });
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

            var connection = _connections.Register(new ConnectionRegistration(ConnectionProtocols.Sftp,
                DisplayEndPoint(e.RemoteEndPoint), reason => e.DisconnectAsync(DisconnectReason.ByApplication, reason)));
            var connectionId = connection.Id;
            // Subscribed before the session starts, so a session always leaves the registry (also when the handshake fails).
            e.Disconnected += (s, args) => _connections.Unregister(connectionId);
            e.KeysExchanged += (s, args) =>
            {
                if (e.ClientVersion != null)
                    _connections.SetClientVersion(connectionId, e.ClientVersion);
            };

            _logger.LogInformation("Accepted a client from {RemoteEndPoint} (connection {ConnectionId}).", e.RemoteEndPoint, connectionId);

            var timeouts = SessionTimeouts.FromSettings(_settingsRepository.ServerSettings);
            if (timeouts.KeepaliveInterval is { } keepalive)
                e.ConfigureKeepalive(keepalive);

            e.ServiceRegistered += (s, service) => OnServiceRegistered(e, service, connectionId);
        }

        /// <summary>The client address for the registry: an IPv4 client of the dual-stack listener as "127.0.0.1:50000", not "[::ffff:127.0.0.1]:50000".</summary>
        internal static string DisplayEndPoint(EndPoint endPoint) => endPoint switch
        {
            IPEndPoint { Address.IsIPv4MappedToIPv6: true } ip => new IPEndPoint(ip.Address.MapToIPv4(), ip.Port).ToString(),
            null => "?",
            _ => endPoint.ToString(),
        };

        void OnServiceRegistered(Session session, SshService e, Guid connectionId)
        {
            _logger.LogDebug("Session {RemoteEndPoint} requesting {Service}.", session.RemoteEndPoint, e.GetType().Name);

            if (e is UserAuthService authService)
            {
                var attempt = new AuthAttempt();
                authService.UserAuth += (s, args) => OnUserAuth(authService, args, attempt, connectionId);
                authService.PartialSucceed += (s, args) => OnUserAuthPartiallySucceeded(authService, args, attempt);
                authService.Succeed += (s, serviceName) => OnUserAuthSucceeded(session, attempt, connectionId);
            }
            else if (e is ConnectionService connectionService)
            {
                connectionService.SubsystemRequested += (s, args) => OnSubsystemRequested(session, args, connectionId);

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

        /// <summary>The login state of one session.</summary>
        private sealed class AuthAttempt
        {
            /// <summary>The steps of a multi-step login that are done.</summary>
            public readonly AuthenticationProgress Progress = new();

            /// <summary>The user and method of the last accepted request (set when the login is complete).</summary>
            public volatile string AcceptedUsername;
            public volatile string AcceptedMethod;

            /// <summary>The user and method of the last request that was accepted as one step of a multi-step login.</summary>
            public User PendingUser;
            public AuthMethods PendingMethod;
        }

        void OnUserAuth(UserAuthService service, UserAuthArgs e, AuthAttempt attempt, Guid connectionId)
        {
            e.Result = false;
            e.PartialSuccess = false;
            attempt.AcceptedUsername = null;
            attempt.PendingUser = null;
            var failure = Authenticate(e, attempt, out var user, out var method);
            service.AuthenticationsThatCanContinue = attempt.Progress.MethodsThatCanContinue(user)
                ?? FailureMessage.DefaultAuthenticationsThatCanContinue;

            if (e.Result)
            {
                if (!attempt.Progress.IsLastStep(user))
                {
                    // Partial success (RFC 4252 section 5.1): FxSsh calls OnUserAuthPartiallySucceeded after the check.
                    e.PartialSuccess = true;
                    attempt.PendingUser = user;
                    attempt.PendingMethod = method;
                    return;
                }
                attempt.AcceptedMethod = attempt.Progress.Describe(method);
                attempt.AcceptedUsername = e.Username;
                return;
            }

            if (e.AuthMethod != "none") // clients try "none" first to get the list of methods
                Publish(new AuthEvent(AuthEventType.LoginFailed)
                {
                    Timestamp = Now, Username = e.Username, RemoteIp = RemoteIp(e.Session), Protocol = SshProtocol,
                    Method = e.AuthMethod, Reason = failure, SessionId = connectionId.ToString(),
                });
            if (e.AuthMethod == "password")
                RecordFailedLogin(e.Session);
            // Failed public keys are not counted: clients offer each key of their agent, so a user with several keys
            // would be banned. A wrong public key cannot be guessed like a password.
        }

        /// <summary>One step of a multi-step login is verified (for a public key: after the signature check).</summary>
        void OnUserAuthPartiallySucceeded(UserAuthService service, UserAuthArgs e, AuthAttempt attempt)
        {
            var user = attempt.PendingUser;
            if (user == null)
                return;
            attempt.Progress.CompleteStep(user, attempt.PendingMethod);
            var next = attempt.Progress.MethodsThatCanContinue(user) ?? FailureMessage.DefaultAuthenticationsThatCanContinue;
            service.AuthenticationsThatCanContinue = next;
            _logger.LogInformation("Step {Step} of the login of {Username} ({Method}) succeeded; the next step is {Next}.",
                attempt.Progress.Completed.Count, e.Username, e.AuthMethod, string.Join(",", next));
        }

        /// <summary>
        /// Sets <c>e.Result</c>; returns why the authentication failed (for the events), or null. <paramref name="user"/>
        /// is the stored user (null when it is unknown), <paramref name="method"/> the method of the request.
        /// </summary>
        string Authenticate(UserAuthArgs e, AuthAttempt attempt, out User user, out AuthMethods method)
        {
            method = AuthMethodRules.FromSshName(e.AuthMethod);
            user = null;
            if (e.Session.RemoteEndPoint is IPEndPoint remote && _bans.IsBanned(remote.Address))
            {
                // Banned while this session was open: no more attempts on it.
                _logger.LogInformation("Authentication ({Method}) of {Username} refused: {RemoteEndPoint} is banned.",
                    e.AuthMethod, e.Username, e.Session.RemoteEndPoint);
                return "the address is banned";
            }

            user = e.Username == null ? null : _settingsRepository.GetUser(e.Username);
            if (user == null)
            {
                attempt.Progress.Reset();
                if (method == AuthMethods.Password)
                    UserLogics.SimulatePasswordCheck(); // same time as for a real user
                _logger.LogInformation("Authentication ({Method}) failed for unknown user {Username} from {RemoteEndPoint}.",
                    e.AuthMethod, e.Username, e.Session.RemoteEndPoint);
                return "unknown user";
            }

            if (!UserLogics.VerifyUserIpWhitelisted(user, e.Session.RemoteEndPoint))
            {
                _logger.LogInformation("Client {RemoteEndPoint} is not in the IP whitelist of user {Username}.",
                    e.Session.RemoteEndPoint, e.Username);
                return "the address is not in the whitelist of the user";
            }

            if (!user.AllowedProtocols.Allows(UserProtocols.Sftp))
            {
                // The same failure as a wrong credential (SSH has no "forbidden"), also in time.
                if (method == AuthMethods.Password)
                    UserLogics.SimulatePasswordCheck();
                _logger.LogInformation("Authentication ({Method}) of {Username} refused: SFTP is not an allowed protocol of the user.",
                    e.AuthMethod, e.Username);
                return "the protocol is not allowed for the user";
            }

            var refusal = attempt.Progress.Check(user, method);
            if (refusal != null)
            {
                if (method == AuthMethods.Password)
                    UserLogics.SimulatePasswordCheck(); // the same time as a wrong password
                _logger.LogInformation("Authentication ({Method}) of {Username} refused: {Reason}.", e.AuthMethod, e.Username, refusal);
                return refusal;
            }

            switch (method)
            {
                case AuthMethods.PublicKey:
                    e.Result = UserLogics.VerifyUserKey(user, e.Key, Now.UtcDateTime);
                    _logger.LogInformation("Public key authentication of {Username}, {KeyAlgorithm} SHA256:{Fingerprint}. Successful: {Result}",
                        e.Username, e.KeyAlgorithm, e.Fingerprint, e.Result);
                    return e.Result ? null : "the public key is not accepted";
                case AuthMethods.Password:
                    e.Result = AppPasswordGenerator.Find(user, e.Password, UserProtocols.Sftp, Now.UtcDateTime) != null
                        || UserLogics.VerifyUserPassword(user, e.Password, _settingsRepository, _logger);
                    _logger.LogInformation("Password authentication of {Username}. Successful: {Result}", e.Username, e.Result);
                    return e.Result ? null : "wrong password";
                default:
                    _logger.LogInformation("Authentication method {Method} is not supported (user {Username}).", e.AuthMethod, e.Username);
                    return "the method is not supported";
            }
        }

        void RecordFailedLogin(Session session)
        {
            if (session.RemoteEndPoint is not IPEndPoint remote)
                return;

            var settings = _settingsRepository.ServerSettings;
            if (_bans.RecordFailure(remote.Address, BanPolicy.FromSettings(settings)))
            {
                _logger.LogWarning("Banned {Address} for {Seconds} s after {Failures} failed logins within {Window} s.",
                    CidrNotation.Normalize(remote.Address), settings.BanDurationSeconds, settings.MaxLoginAttemptsBeforeBan,
                    settings.LoginFailureWindowSeconds);
                Publish(new AuthEvent(AuthEventType.IpBanned)
                {
                    Timestamp = Now, RemoteIp = CidrNotation.Normalize(remote.Address).ToString(), Protocol = SshProtocol,
                    Reason = $"{settings.MaxLoginAttemptsBeforeBan} failed logins within {settings.LoginFailureWindowSeconds} s; banned for {settings.BanDurationSeconds} s",
                });
            }
        }

        /// <summary>Called after the whole authentication succeeded (for a public key: after the signature check).</summary>
        void OnUserAuthSucceeded(Session session, AuthAttempt attempt, Guid connectionId)
        {
            var username = attempt.AcceptedUsername;
            if (username == null)
                return;

            var method = attempt.AcceptedMethod;
            _connections.SetAuthenticated(connectionId, username, method);
            Publish(new AuthEvent(AuthEventType.LoginOk)
            {
                Timestamp = Now, Username = username, RemoteIp = RemoteIp(session), Protocol = SshProtocol, Method = method,
                SessionId = connectionId.ToString(),
            });
            session.Disconnected += (s, args) => Publish(new AuthEvent(AuthEventType.Logout)
            {
                Timestamp = Now, Username = username, RemoteIp = RemoteIp(session), Protocol = SshProtocol, Method = method,
                SessionId = connectionId.ToString(),
            });

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

        void OnSubsystemRequested(Session session, SubsystemRequestedArgs e, Guid connectionId)
        {
            _logger.LogInformation("Channel {ChannelId} requested subsystem \"{Name}\".", e.Channel.ServerChannelId, e.Name);

            if (e.Name != "sftp" || !e.AttachedUserAuthArgs.Result)
                return; // Agreed stays false: the server answers SSH_MSG_CHANNEL_FAILURE

            var username = e.AttachedUserAuthArgs.Username;
            var user = _settingsRepository.GetUser(username);
            if (user == null)
                return;

            IFileSystem storage;
            try
            {
                storage = SyncBridge.Wait(_fileSystemFactory.CreateAsync(user, new ClientContext(ConnectionProtocols.Sftp, RemoteIp(session), connectionId), CancellationToken.None));
            }
            catch (Exception ex) when (ex is ArgumentException or FileSystemException or System.Collections.Generic.KeyNotFoundException)
            {
                _logger.LogError(ex, "The storage of user {Username} cannot be created; the SFTP subsystem is refused.", user.Username);
                return;
            }

            var fileSystem = new SftpFileSystemAdapter(storage, _logger, user.Username);
            new SftpService(fileSystem).Attach(e.Channel);
            e.Agreed = true;
        }

        private DateTimeOffset Now => _bans.Time.GetUtcNow();

        private static string RemoteIp(Session session)
            => session.RemoteEndPoint is IPEndPoint remote ? CidrNotation.Normalize(remote.Address).ToString() : session.RemoteEndPoint?.ToString();

        /// <summary>
        /// Publishes an event from the synchronous SSH callbacks. The bus only queues it, so this returns at once unless
        /// the queue of a sink is full. A failure never breaks the SSH session.
        /// </summary>
        private void Publish(IEvent @event)
        {
            if (_events == null)
                return;
            try
            {
                SyncBridge.Wait(_events.PublishAsync(@event, CancellationToken.None));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Could not publish the {Category} event {Type}.", @event.Category, @event.TypeName);
            }
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
