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
using SshServer.Interfaces.Users;
using SshServer.Interfaces.TwoFactor;
using SshServerModule.Sftp;
using SshServerModule.Authentication;
using SshServerModule.Proxy;
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
        private readonly IEffectiveUserSettingsService _userSettings;
        private readonly ITwoFactorVerifier _twoFactor;
        private readonly ProxyProtocolOptions _proxy;
        private readonly IUserAuthenticator _authenticator;

        /// <summary>The prompt of the TOTP verification code (keyboard-interactive, echo off).</summary>
        internal const string CodePrompt = "Verification code: ";

        /// <summary>The prompt of the password when keyboard-interactive is the password step (echo off).</summary>
        internal const string PasswordPrompt = "Password: ";

        /// <summary>The protocol name of the auth events.</summary>
        internal const string SshProtocol = "SSH";

        /// <param name="options">Port and bind addresses from the configuration; they override the stored settings. Null: stored settings only.</param>
        /// <param name="banTracker">The auto-ban state, shared with the admin UI (AddSshServerSecurity). Null: a private one.</param>
        /// <param name="connections">The open connections, shared with the admin UI (AddSshServerConnections). Null: a private registry.</param>
        /// <param name="events">The event bus for the auth and system events (AddSshServerEvents). Null: no events.</param>
        /// <param name="userSettings">The effective settings of the users with their groups (AddSshServerStorage). Null: one over <paramref name="settingsRepository"/>.</param>
        /// <param name="twoFactor">The TOTP second factor (AddTwoFactor, #63). Null: no user has a second factor.</param>
        /// <param name="proxy">The PROXY protocol of a load balancer (AddSshServerListenOptions, #75). Null or no allowed source: off.</param>
        /// <param name="authenticator">The credential check with the authentication providers (AddSshServerAuthentication, #64). Null: the database only.</param>
        public HostedServer(ILogger<HostedServer> logger, IFileSystemFactory fileSystemFactory, ISettingsRepository settingsRepository,
            LoginBanTracker banTracker = null, IOptions<SshServerOptions> options = null, IConnectionRegistry connections = null,
            IEventBus events = null, ITwoFactorVerifier twoFactor = null, IEffectiveUserSettingsService userSettings = null,
            IUserAuthenticator authenticator = null, ProxyProtocolOptions proxy = null)
        {
            _proxy = proxy;
            _twoFactor = twoFactor;
            _userSettings = userSettings ?? new EffectiveUserSettingsService(settingsRepository);
            _connections = connections ?? new ConnectionRegistry(TimeProvider.System);
            _options = options?.Value;
            _events = events;
            _logger = logger;
            _settingsRepository = settingsRepository;
            _fileSystemFactory = fileSystemFactory;
            _bans = banTracker ?? new LoginBanTracker(TimeProvider.System);
            _ipFilter = new IpFilter(logger);
            _authenticator = authenticator ?? new UserAuthenticator(
                [new DatabaseAuthenticationProvider(settingsRepository, null, _bans.Time)], settingsRepository);
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
            if (_proxy?.Enabled == true)
                _logger.LogInformation("PROXY protocol on: connections only from {Sources}, each with a PROXY header.",
                    string.Join(", ", _proxy.AllowedSources));

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
                    if (_proxy?.Enabled == true)
                        server.ConnectionPreface = async (socket, ct) => await _proxy.AcceptAsync(socket, ct);
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
            /// <summary>The session limit of the accepted user (<see cref="User.MaxSessions"/>), checked again at the login.</summary>
            public volatile int AcceptedMaxSessions;

            /// <summary>The user and method of the last request that was accepted as one step of a multi-step login.</summary>
            public User PendingUser;
            public AuthMethods PendingMethod;
            public bool PendingTotp;

            /// <summary>True when the open keyboard-interactive prompt asks for the verification code, false: the password.</summary>
            public bool PromptAsksForCode;

            /// <summary>
            /// The user that an external authentication provider returned with the last accepted request (#64), saved when
            /// the step is verified (for a public key: after the signature check). Null: nothing to save.
            /// </summary>
            public CredentialCheck Provisioned;
        }

        void OnUserAuth(UserAuthService service, UserAuthArgs e, AuthAttempt attempt, Guid connectionId)
        {
            e.Result = false;
            e.PartialSuccess = false;
            e.InfoRequest = null;
            attempt.AcceptedUsername = null;
            attempt.PendingUser = null;
            attempt.Provisioned = null;

            // Keyboard-interactive (RFC 4256): the request only gets the prompt; the response is checked below.
            if (e.AuthMethod == AuthMethodRules.KeyboardInteractiveName && e.Responses == null && SendPrompt(e, attempt))
                return;

            var failure = Authenticate(e, attempt, connectionId, out var user, out var method, out var totp);
            service.AuthenticationsThatCanContinue = attempt.Progress.MethodsThatCanContinue(user, totp)
                ?? FailureMessage.DefaultAuthenticationsThatCanContinue;

            if (e.Result)
            {
                if (!attempt.Progress.IsLastStep(user, totp))
                {
                    // Partial success (RFC 4252 section 5.1): FxSsh calls OnUserAuthPartiallySucceeded after the check.
                    e.PartialSuccess = true;
                    attempt.PendingUser = user;
                    attempt.PendingMethod = method;
                    attempt.PendingTotp = totp;
                    return;
                }
                attempt.AcceptedMethod = attempt.Progress.Describe(method);
                attempt.AcceptedMaxSessions = user.MaxSessions;
                attempt.AcceptedUsername = e.Username;
                return;
            }

            if (e.AuthMethod != "none") // clients try "none" first to get the list of methods
                Publish(new AuthEvent(AuthEventType.LoginFailed)
                {
                    Timestamp = Now, Username = e.Username, RemoteIp = RemoteIp(e.Session), Protocol = SshProtocol,
                    Method = e.AuthMethod, Reason = failure, SessionId = connectionId.ToString(),
                });
            if (e.AuthMethod == "password" || e.Responses != null) // a password, or a password or code over keyboard-interactive
                RecordFailedLogin(e.Session);
            // Failed public keys are not counted: clients offer each key of their agent, so a user with several keys
            // would be banned. A wrong public key cannot be guessed like a password.
        }

        /// <summary>
        /// Sets the prompt of a keyboard-interactive request: the verification code when it is the code step of the user,
        /// otherwise the password. An unknown user or a refused method gets the password prompt too, and fails with the
        /// response, so the prompt does not tell whether a user exists. False when no prompt is sent (a banned address).
        /// </summary>
        bool SendPrompt(UserAuthArgs e, AuthAttempt attempt)
        {
            if (e.Session.RemoteEndPoint is IPEndPoint remote && _bans.IsBanned(remote.Address))
                return false;

            var user = _settingsRepository.GetUser(e.Username);
            var asksForCode = false;
            if (user != null && TwoFactorEnabled(user) is { } totp && attempt.Progress.Check(user, AuthMethods.KeyboardInteractive, totp) == null)
                asksForCode = attempt.Progress.KeyboardInteractiveAsksForCode(user, totp);

            attempt.PromptAsksForCode = asksForCode;
            e.InfoRequest = new KeyboardInteractiveInfoRequest("", "",
                [new KeyboardInteractivePrompt(asksForCode ? CodePrompt : PasswordPrompt, false)]);
            return true;
        }

        /// <summary>One step of a multi-step login is verified (for a public key: after the signature check).</summary>
        void OnUserAuthPartiallySucceeded(UserAuthService service, UserAuthArgs e, AuthAttempt attempt)
        {
            var user = attempt.PendingUser;
            if (user == null)
                return;
            if (attempt.Provisioned != null && !_authenticator.Save(attempt.Provisioned))
            {
                // The next step finds no stored user and asks the provider again; the login is complete only when it is saved.
                _logger.LogWarning("User {Username} of the authentication provider {Provider} could not be saved after step {Step}.",
                    LogText.Clean(e.Username), attempt.Provisioned.Provider, attempt.Progress.Completed.Count + 1);
            }
            attempt.Provisioned = null;
            attempt.Progress.CompleteStep(user, attempt.PendingMethod, attempt.PendingTotp);
            var next = attempt.Progress.MethodsThatCanContinue(user, attempt.PendingTotp) ?? FailureMessage.DefaultAuthenticationsThatCanContinue;
            service.AuthenticationsThatCanContinue = next;
            _logger.LogInformation("Step {Step} of the login of {Username} ({Method}) succeeded; the next step is {Next}.",
                attempt.Progress.Completed.Count, LogText.Clean(e.Username), LogText.Clean(e.AuthMethod), string.Join(",", next));
        }

        /// <summary>
        /// Whether the user has a TOTP second factor. Null when it cannot be read: then the login is refused (fail closed).
        /// </summary>
        bool? TwoFactorEnabled(User user)
        {
            if (_twoFactor == null)
                return false;
            try
            {
                return SyncBridge.Wait(new ValueTask<bool>(_twoFactor.IsEnabledAsync(TwoFactorSubject.ForUser(user), CancellationToken.None)));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "The second factor of user {Username} cannot be read; the login is refused.", user.Username);
                return null;
            }
        }

        /// <summary>
        /// Sets <c>e.Result</c>; returns why the authentication failed (for the events), or null. <paramref name="user"/>
        /// is the user to log in (null when it is unknown; a user of an external provider that is not saved yet, #64),
        /// <paramref name="method"/> the method of the request, <paramref name="totp"/> whether the user has a TOTP second
        /// factor.
        /// </summary>
        string Authenticate(UserAuthArgs e, AuthAttempt attempt, Guid connectionId, out User user, out AuthMethods method, out bool totp)
        {
            method = AuthMethodRules.FromSshName(e.AuthMethod);
            user = null;
            totp = false;
            // A keyboard-interactive response to the password prompt costs the time of a password check in every case.
            var passwordLike = method == AuthMethods.Password
                               || (method == AuthMethods.KeyboardInteractive && e.Responses != null && !attempt.PromptAsksForCode);
            if (e.Session.RemoteEndPoint is IPEndPoint remote && _bans.IsBanned(remote.Address))
            {
                // Banned while this session was open: no more attempts on it.
                _logger.LogInformation("Authentication ({Method}) of {Username} refused: {RemoteEndPoint} is banned.",
                    LogText.Clean(e.AuthMethod), LogText.Clean(e.Username), e.Session.RemoteEndPoint);
                return "the address is banned";
            }

            user = e.Username == null ? null : _settingsRepository.GetUser(e.Username);
            var request = CredentialRequest(e, method, passwordLike, user);
            if (user == null && (request == null || !_authenticator.HasExternalProviders))
            {
                attempt.Progress.Reset();
                if (passwordLike)
                    UserLogics.SimulatePasswordCheck(); // same time as for a real user
                _logger.LogInformation("Authentication ({Method}) failed for unknown user {Username} from {RemoteEndPoint}.",
                    LogText.Clean(e.AuthMethod), LogText.Clean(e.Username), e.Session.RemoteEndPoint);
                return "unknown user";
            }

            if (user != null)
            {
                // Refused like a wrong credential, in the same time (#61, #64).
                var refusal = CheckLogin(e, attempt, connectionId, user, method, passwordLike, out totp);
                if (refusal != null)
                {
                    if (passwordLike)
                        SyncBridge.Wait(_authenticator.SpendFailureTimeAsync(request, CancellationToken.None));
                    return refusal;
                }
            }

            switch (method)
            {
                case AuthMethods.PublicKey:
                case AuthMethods.Password:
                    return VerifyCredential(e, attempt, connectionId, request, ref user, ref totp);
                case AuthMethods.KeyboardInteractive:
                    return VerifyKeyboardInteractive(e, attempt, connectionId, request, ref user, ref totp);
                default:
                    _logger.LogInformation("Authentication method {Method} is not supported (user {Username}).", LogText.Clean(e.AuthMethod), LogText.Clean(e.Username));
                    return "the method is not supported";
            }
        }

        /// <summary>
        /// The credential of a password or public key request for the authentication providers (#64), or null for a request
        /// without one (the verification code, "none", an unknown method).
        /// </summary>
        static AuthRequest CredentialRequest(UserAuthArgs e, AuthMethods method, bool passwordLike, User user)
        {
            if (e.Username == null)
                return null;
            if (method == AuthMethods.PublicKey && e.Key != null)
                return new AuthRequest { Username = e.Username, Method = method, PublicKey = e.Key, RemoteIp = RemoteIp(e.Session), Protocol = SshProtocol, StoredUser = user };
            if (!passwordLike)
                return null;
            var password = method == AuthMethods.Password ? e.Password ?? "" : (e.Responses is [var single] ? single : null) ?? "";
            return new AuthRequest { Username = e.Username, Method = method, Password = password, RemoteIp = RemoteIp(e.Session), Protocol = SshProtocol, StoredUser = user };
        }

        /// <summary>
        /// The checks before the credential (#61): status, expiry, password age, session limit, the networks of the user,
        /// its second factor and the steps of its login. Returns the reason of a refusal, or null; the caller spends the
        /// time of a wrong password.
        /// </summary>
        string CheckLogin(UserAuthArgs e, AuthAttempt attempt, Guid connectionId, User user, AuthMethods method, bool passwordLike, out bool totp)
        {
            totp = false;
            // A password over keyboard-interactive is a password too (for the password age).
            var lifecycle = UserLoginRules.Refusal(user, passwordLike ? AuthMethods.Password : method, Now.UtcDateTime,
                                _settingsRepository.ServerSettings.PasswordMaxAgeDays)
                            ?? UserLoginRules.SessionLimitRefusal(user, _connections.CountSessions(user.Username, connectionId));
            if (lifecycle != null)
            {
                _logger.LogInformation("Authentication ({Method}) of {Username} from {RemoteEndPoint} refused: {Reason}.",
                    LogText.Clean(e.AuthMethod), LogText.Clean(e.Username), e.Session.RemoteEndPoint, lifecycle);
                return lifecycle;
            }

            var settings = _userSettings.Resolve(user);
            if (!UserLogics.VerifyUserIpWhitelisted(settings.AllowedIps, e.Session.RemoteEndPoint))
            {
                _logger.LogInformation("Client {RemoteEndPoint} is not in the allowed networks of user {Username} ({Origin}).",
                    e.Session.RemoteEndPoint, LogText.Clean(e.Username), settings.AllowedIpsOrigin);
                return "the address is not in the whitelist of the user";
            }

            if (!user.AllowedProtocols.Allows(UserProtocols.Sftp))
            {
                // The same failure as a wrong credential (SSH has no "forbidden"), also in time (the caller spends it).
                _logger.LogInformation("Authentication ({Method}) of {Username} refused: SFTP is not an allowed protocol of the user.",
                    LogText.Clean(e.AuthMethod), LogText.Clean(e.Username));
                return "the protocol is not allowed for the user";
            }

            if (TwoFactorEnabled(user) is not { } hasTotp)
                return "the second factor cannot be checked";
            totp = hasTotp;

            var refusal = attempt.Progress.Check(user, method, totp, settings.AllowedAuthMethods);
            if (refusal != null)
            {
                _logger.LogInformation("Authentication ({Method}) of {Username} refused: {Reason}.", LogText.Clean(e.AuthMethod), LogText.Clean(e.Username), refusal);
                return refusal;
            }
            return null;
        }

        /// <summary>
        /// Checks a password or public key with the authentication providers (#64). A user that an external provider
        /// created or changed is checked again with its new settings and saved when the step is verified.
        /// </summary>
        string VerifyCredential(UserAuthArgs e, AuthAttempt attempt, Guid connectionId, AuthRequest request, ref User user, ref bool totp)
        {
            // An app password of the user for SFTP (#71) is a local credential, also for a user of a provider.
            if (user != null && request.Method == AuthMethods.Password
                && AppPasswordGenerator.Find(user, request.Password, UserProtocols.Sftp, Now.UtcDateTime) != null)
            {
                _logger.LogInformation("Password authentication of {Username} with an app password. Successful: True", LogText.Clean(e.Username));
                e.Result = true;
                return null;
            }

            var check = SyncBridge.Wait(_authenticator.VerifyAsync(request, CancellationToken.None));
            if (request.PublicKey != null)
                _logger.LogInformation("Public key authentication of {Username}, {KeyAlgorithm} SHA256:{Fingerprint} ({Provider}). Successful: {Result}",
                    LogText.Clean(e.Username), LogText.Clean(e.KeyAlgorithm), e.Fingerprint, check.Provider, check.Succeeded);
            else
                _logger.LogInformation("Password authentication{Variant} of {Username} ({Provider}). Successful: {Result}",
                    request.Method == AuthMethods.KeyboardInteractive ? " (keyboard-interactive)" : "", LogText.Clean(e.Username), check.Provider, check.Succeeded);

            if (!check.Succeeded)
            {
                if (user == null)
                    attempt.Progress.Reset(); // as for an unknown user
                return check.Reason;
            }

            if (check.NeedsSave)
            {
                // The credential time is spent: a refusal here costs nothing more.
                var refusal = CheckLogin(e, attempt, connectionId, check.User, request.Method, request.IsPassword, out var hasTotp);
                if (refusal != null)
                    return refusal;
                totp = hasTotp;
                attempt.Provisioned = check;
            }
            user = check.User;
            e.Result = true;
            return null;
        }

        /// <summary>Checks the response to the keyboard-interactive prompt: the verification code or the password.</summary>
        string VerifyKeyboardInteractive(UserAuthArgs e, AuthAttempt attempt, Guid connectionId, AuthRequest request, ref User user, ref bool totp)
        {
            if (user != null && attempt.PromptAsksForCode != attempt.Progress.KeyboardInteractiveAsksForCode(user, totp))
            {
                // The second factor of the user changed between the prompt and the response.
                if (!attempt.PromptAsksForCode)
                    SyncBridge.Wait(_authenticator.SpendFailureTimeAsync(request, CancellationToken.None));
                _logger.LogInformation("Keyboard-interactive authentication of {Username} refused: the login changed during the prompt.", LogText.Clean(e.Username));
                return "the login changed during the prompt";
            }

            if (!attempt.PromptAsksForCode)
                return VerifyCredential(e, attempt, connectionId, request, ref user, ref totp);

            var answer = e.Responses is [var single] ? single : null;
            TwoFactorCheck check;
            try
            {
                check = SyncBridge.Wait(new ValueTask<TwoFactorCheck>(_twoFactor.VerifyAsync(TwoFactorSubject.ForUser(user), answer, CancellationToken.None)));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "The verification code of user {Username} cannot be checked; the login is refused.", LogText.Clean(e.Username));
                return "the second factor cannot be checked";
            }

            e.Result = check is TwoFactorCheck.Valid or TwoFactorCheck.RecoveryCode;
            if (check == TwoFactorCheck.RecoveryCode)
                _logger.LogWarning("User {Username} logged in with a recovery code from {RemoteEndPoint}.", LogText.Clean(e.Username), e.Session.RemoteEndPoint);
            else
                _logger.LogInformation("Verification code of {Username}: {Result}.", LogText.Clean(e.Username), check);
            return check switch
            {
                TwoFactorCheck.Valid or TwoFactorCheck.RecoveryCode => null,
                TwoFactorCheck.Replayed => "the verification code was used already",
                TwoFactorCheck.LockedOut => "too many wrong verification codes",
                TwoFactorCheck.NotEnabled => "the second factor is not set up any more",
                _ => "wrong verification code",
            };
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
            if (attempt.Provisioned is { } provisioned)
            {
                attempt.Provisioned = null;
                if (!_authenticator.Save(provisioned))
                {
                    const string reason = "the user of the authentication provider cannot be saved";
                    _logger.LogWarning("The login of {Username} from {RemoteEndPoint} is refused: {Reason}.", LogText.Clean(username), session.RemoteEndPoint, reason);
                    Publish(new AuthEvent(AuthEventType.LoginFailed)
                    {
                        Timestamp = Now, Username = username, RemoteIp = RemoteIp(session), Protocol = SshProtocol, Method = method,
                        Reason = reason, SessionId = connectionId.ToString(),
                    });
                    _ = session.DisconnectAsync(DisconnectReason.ByApplication, "The login cannot be completed.");
                    return;
                }
            }
            if (!_connections.TrySetAuthenticated(connectionId, username, method, attempt.AcceptedMaxSessions))
            {
                // Another login of the user took the last session between the check and now (issue #61).
                var reason = UserLoginRules.SessionLimitReason(attempt.AcceptedMaxSessions);
                _logger.LogInformation("The login of {Username} from {RemoteEndPoint} is refused: {Reason}.", LogText.Clean(username), session.RemoteEndPoint, reason);
                Publish(new AuthEvent(AuthEventType.LoginFailed)
                {
                    Timestamp = Now, Username = username, RemoteIp = RemoteIp(session), Protocol = SshProtocol, Method = method,
                    Reason = reason, SessionId = connectionId.ToString(),
                });
                _ = session.DisconnectAsync(DisconnectReason.TooManyConnections, "Too many sessions of the user.");
                return;
            }
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
                user.LastLoginAt = _bans.Time.GetUtcNow().UtcDateTime;
                if (!_settingsRepository.UpdateUser(user))
                    _logger.LogWarning("Could not save the last login time of user {Username}.", username);
            }
            catch (Exception ex)
            {
                // The login itself is fine; only the time stamp is lost.
                _logger.LogWarning(ex, "Could not save the last login time of user {Username} from {RemoteEndPoint}.",
                    LogText.Clean(username), session.RemoteEndPoint);
            }
        }

        void OnSubsystemRequested(Session session, SubsystemRequestedArgs e, Guid connectionId)
        {
            _logger.LogInformation("Channel {ChannelId} requested subsystem \"{Name}\".", e.Channel.ServerChannelId, e.Name);

            if (e.Name != "sftp" || !e.AttachedUserAuthArgs.Result)
                return; // Agreed stays false: the server answers SSH_MSG_CHANNEL_FAILURE
            if (_connections.Get(connectionId)?.Username == null)
                return; // the login was refused when it was recorded (session limit); the session is being closed

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
