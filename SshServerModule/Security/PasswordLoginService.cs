#nullable enable
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Net;
using SshServer.Interfaces.TwoFactor;
using SshServer.Interfaces.Users;

namespace FxSsh.SshServerModule.Security
{
    /// <summary>The outcome of <see cref="PasswordLoginService.LoginAsync"/>.</summary>
    public enum PasswordLoginStatus
    {
        /// <summary>The credentials are valid and the user may use the protocol.</summary>
        Ok,

        /// <summary>The address may not connect: global blacklist or whitelist mode, or an auto-ban. Nothing was checked.</summary>
        AddressRefused,

        /// <summary>Unknown user, wrong password, or a user that cannot log in with a password alone. Counted for the auto-ban.</summary>
        Failed,

        /// <summary>The credentials are valid, but <see cref="User.AllowedProtocols"/> does not have the protocol.</summary>
        ProtocolNotAllowed,
    }

    /// <summary>The result of a password login.</summary>
    /// <param name="Status">The outcome.</param>
    /// <param name="User">The user, for <see cref="PasswordLoginStatus.Ok"/>; otherwise null.</param>
    /// <param name="Method">"password" or "app-password", for <see cref="PasswordLoginStatus.Ok"/>.</param>
    /// <param name="Reason">Why the login failed, for the log and the events (never for the client).</param>
    public sealed record PasswordLoginResult(PasswordLoginStatus Status, User? User, string? Method, string? Reason);

    /// <summary>
    /// The user name and password login of the protocols that are not SSH (WebDAV #71, later FTP #72): the same rules as
    /// the SFTP login of <c>HostedServer</c>, in one place.
    /// <list type="number">
    /// <item>The global IP rules and the auto-ban (<see cref="IpFilter"/>, <see cref="LoginBanTracker"/>).</item>
    /// <item>The lifecycle of the user (#61, <see cref="UserLoginRules"/>: status and expiry; the password age for the
    /// password), its effective allowed networks (its own or of its groups) and the password: the stored PBKDF2 hash (the
    /// effective login methods must allow the password; a user with a multi-step login or a TOTP second factor (#63)
    /// cannot log in with the password alone, because these protocols cannot ask for a second step), or an app password
    /// of the user for the protocol (<see cref="User.AppPasswords"/>).</item>
    /// <item>The protocol (<see cref="User.AllowedProtocols"/>), checked after the credentials, so only the owner of the
    /// account learns that the protocol is refused.</item>
    /// </list>
    /// A failure takes the time of a key derivation (also for an unknown user), counts for the auto-ban and gives a
    /// <c>LoginFailed</c> event; a new ban gives an <c>IpBanned</c> event. The caller checks the session limit
    /// (<c>IConnectionRegistry.TrySetAuthenticated</c>) and publishes <c>LoginOk</c> and <c>Logout</c>, because it knows the session.
    /// </summary>
    public sealed class PasswordLoginService
    {
        public const string PasswordMethod = AuthMethodRules.PasswordName;
        public const string AppPasswordMethod = "app-password";

        private readonly ISettingsRepository _repository;
        private readonly LoginBanTracker _bans;
        private readonly IEventBus? _events;
        private readonly ILogger _logger;
        private readonly IpFilter _ipFilter;
        private readonly ITwoFactorVerifier? _twoFactor;
        private readonly IEffectiveUserSettingsService _userSettings;

        /// <param name="events">The event bus (AddSshServerEvents). Null: no events.</param>
        /// <param name="twoFactor">The second factor (#63). Null: no user has one.</param>
        /// <param name="userSettings">The effective settings of the users with their groups (AddSshServerStorage). Null: one over <paramref name="repository"/>.</param>
        public PasswordLoginService(ISettingsRepository repository, LoginBanTracker bans, ILogger<PasswordLoginService> logger, IEventBus? events = null,
            ITwoFactorVerifier? twoFactor = null, IEffectiveUserSettingsService? userSettings = null)
        {
            _twoFactor = twoFactor;
            _userSettings = userSettings ?? new EffectiveUserSettingsService(repository);
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));
            _bans = bans ?? throw new ArgumentNullException(nameof(bans));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _events = events;
            _ipFilter = new IpFilter(logger);
        }

        /// <summary>The clock of the auto-ban, also for the events and the expiry of the app passwords.</summary>
        public TimeProvider Time => _bans.Time;

        /// <summary>Checks only the address (global rules and auto-ban). Use it before anything else of a request.</summary>
        public IpFilterResult CheckAddress(IPAddress remote) =>
            _ipFilter.Check(new IPEndPoint(remote ?? throw new ArgumentNullException(nameof(remote)), 0), _repository.ServerSettings, _bans);

        /// <summary>Checks a user name and password for <paramref name="protocol"/>, from <paramref name="remote"/>.</summary>
        /// <param name="protocolName">The protocol for the events and the log, for example "WebDAV".</param>
        public async ValueTask<PasswordLoginResult> LoginAsync(string protocolName, UserProtocols protocol, string? username, string? password,
            IPAddress remote, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(remote);
            var address = CidrNotation.Normalize(remote);
            var filter = CheckAddress(address);
            if (filter != IpFilterResult.Allowed)
            {
                _logger.LogInformation("{Protocol} login of {Username} refused: {Address} is {Reason}.", protocolName, username, address, filter);
                return new PasswordLoginResult(PasswordLoginStatus.AddressRefused, null, null, $"the address is {filter.ToString().ToLowerInvariant()}");
            }

            var user = string.IsNullOrEmpty(username) ? null : _repository.GetUser(username);
            var (method, failure) = await VerifyAsync(user, password, protocol, address, ct);
            if (failure != null)
            {
                _logger.LogInformation("{Protocol} login of {Username} from {Address} failed: {Reason}.", protocolName, username, address, failure);
                await PublishAsync(new AuthEvent(AuthEventType.LoginFailed)
                {
                    Timestamp = Time.GetUtcNow(), Username = username, RemoteIp = address.ToString(), Protocol = protocolName,
                    Method = PasswordMethod, Reason = failure,
                }, ct);
                await RecordFailureAsync(address, protocolName, ct);
                return new PasswordLoginResult(PasswordLoginStatus.Failed, null, null, failure);
            }

            if (!user!.AllowedProtocols.Allows(protocol))
            {
                const string reason = "the protocol is not allowed for the user";
                _logger.LogInformation("{Protocol} login of {Username} from {Address} refused: {Reason}.", protocolName, username, address, reason);
                await PublishAsync(new AuthEvent(AuthEventType.LoginFailed)
                {
                    Timestamp = Time.GetUtcNow(), Username = user.Username, RemoteIp = address.ToString(), Protocol = protocolName,
                    Method = method, Reason = reason,
                }, ct);
                return new PasswordLoginResult(PasswordLoginStatus.ProtocolNotAllowed, null, method, reason);
            }

            _logger.LogInformation("{Protocol} login of {Username} from {Address} with {Method} succeeded.", protocolName, user.Username, address, method);
            return new PasswordLoginResult(PasswordLoginStatus.Ok, user, method, null);
        }

        /// <summary>Returns the method that succeeded, or the reason of the failure. Every failure costs one key derivation.</summary>
        private async ValueTask<(string? Method, string? Failure)> VerifyAsync(User? user, string? password, UserProtocols protocol,
            IPAddress address, CancellationToken ct)
        {
            if (user == null)
            {
                UserLogics.SimulatePasswordCheck();
                return (null, "unknown user");
            }

            var now = Time.GetUtcNow().UtcDateTime;
            if (UserLoginRules.Refusal(user, AuthMethods.None, now, 0) is { } lifecycle)
            {
                UserLogics.SimulatePasswordCheck();
                return (null, lifecycle);
            }

            var settings = _userSettings.Resolve(user);
            if (!UserLogics.VerifyUserIpWhitelisted(settings.AllowedIps, new IPEndPoint(address, 0)))
            {
                UserLogics.SimulatePasswordCheck();
                return (null, "the address is not in the whitelist of the user");
            }

            if (AppPasswordGenerator.Find(user, password, protocol, now) != null)
                return (AppPasswordMethod, null);

            if ((settings.AllowedAuthMethods & AuthMethods.Password) == 0)
            {
                UserLogics.SimulatePasswordCheck();
                return (null, "the password is not allowed for the user");
            }

            if (UserLoginRules.Refusal(user, AuthMethods.Password, now, _repository.ServerSettings.PasswordMaxAgeDays) is { } passwordAge)
            {
                UserLogics.SimulatePasswordCheck();
                return (null, passwordAge);
            }

            if (AuthMethodRules.RequiredSteps(user).Count > 0)
            {
                UserLogics.SimulatePasswordCheck();
                return (null, "the user has a multi-step login; use an app password");
            }

            bool totp;
            try
            {
                totp = _twoFactor != null && await _twoFactor.IsEnabledAsync(TwoFactorSubject.ForUser(user), ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "The second factor of user {Username} cannot be read; the login is refused.", user.Username);
                UserLogics.SimulatePasswordCheck();
                return (null, "the second factor cannot be checked");
            }
            if (totp)
            {
                UserLogics.SimulatePasswordCheck();
                return (null, "the user has a second factor; use an app password");
            }

            return UserLogics.VerifyUserPassword(user, password, _repository, _logger) ? (PasswordMethod, null) : (null, "wrong password");
        }

        private async ValueTask RecordFailureAsync(IPAddress address, string protocolName, CancellationToken ct)
        {
            var settings = _repository.ServerSettings;
            if (!_bans.RecordFailure(address, BanPolicy.FromSettings(settings)))
                return;
            _logger.LogWarning("Banned {Address} for {Seconds} s after {Failures} failed logins within {Window} s.",
                address, settings.BanDurationSeconds, settings.MaxLoginAttemptsBeforeBan, settings.LoginFailureWindowSeconds);
            await PublishAsync(new AuthEvent(AuthEventType.IpBanned)
            {
                Timestamp = Time.GetUtcNow(), RemoteIp = address.ToString(), Protocol = protocolName,
                Reason = $"{settings.MaxLoginAttemptsBeforeBan} failed logins within {settings.LoginFailureWindowSeconds} s; banned for {settings.BanDurationSeconds} s",
            }, ct);
        }

        private async ValueTask PublishAsync(IEvent @event, CancellationToken ct)
        {
            if (_events == null)
                return;
            try
            {
                await _events.PublishAsync(@event, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Could not publish the {Category} event {Type}.", @event.Category, @event.TypeName);
            }
        }
    }
}
