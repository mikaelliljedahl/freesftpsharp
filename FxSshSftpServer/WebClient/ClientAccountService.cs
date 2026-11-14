using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.SshServerModule;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Audit;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.TwoFactor;
using SshServer.Interfaces.Users;
using SshServer.TwoFactor;

namespace FxSshSftpServer.WebClient
{
    /// <summary>A change that the account page refused; the message is for the user.</summary>
    public sealed class ClientAccountException : Exception
    {
        public ClientAccountException(string message) : base(message)
        {
        }
    }

    /// <summary>
    /// The self-service of the web client (#69) for the signed-in user only: its password (the policy of
    /// <see cref="UserAdministrationService.ValidatePassword"/>, also the forced change of an expired password, #61), its
    /// public keys (#58, through <see cref="UserAdministrationService"/>), its app passwords (#71, #145: for the clients of
    /// WebDAV, FTP and SFTP that cannot do the normal login, also for a user of the single sign-on), its second factor (#63, through
    /// <see cref="TwoFactorService"/>; turning it off or new recovery codes need a current code), and its open sessions
    /// of every protocol. Each method takes the user name of the login; nothing here reaches another user.
    /// </summary>
    public sealed class ClientAccountService
    {
        /// <summary>The <see cref="ProviderEvent.Actor"/> of a change that users make themselves.</summary>
        public const string SelfActor = "self";

        public const string WrongPasswordMessage = "The current password is wrong.";

        private readonly ISettingsRepository _repository;
        private readonly UserAdministrationService _users;
        private readonly TwoFactorService _twoFactor;
        private readonly IConnectionRegistry _connections;
        private readonly IEventBus _events;
        private readonly TimeProvider _time;
        private readonly ILogger<ClientAccountService> _logger;
        private readonly AuditActorContext _actors;

        public ClientAccountService(ISettingsRepository repository, TwoFactorService twoFactor, IConnectionRegistry connections, IEventBus events,
            TimeProvider time, ILogger<ClientAccountService> logger, AuditActorContext actors)
        {
            _repository = repository;
            // The users service on the shared repository: the scoped one of the admin UI checks an administrator.
            _users = new UserAdministrationService(repository);
            _twoFactor = twoFactor;
            _connections = connections;
            _events = events;
            _time = time;
            _logger = logger;
            _actors = actors;
        }

        public User GetUser(string username) => _repository.GetUser(username);

        /// <summary>Sets a new password after a check of the current one. Returns the saved user (for a new login cookie).</summary>
        /// <summary>The external authentication provider that manages the password of the user (#64), or null.</summary>
        public string PasswordManagedBy(string username) => ExternalCredentials.PasswordManagedBy(RequireUser(username));

        public User ChangePassword(string username, string currentPassword, string newPassword, string repeatPassword)
        {
            var user = RequireUser(username);
            if (ExternalCredentials.PasswordManagedBy(user) is { } provider)
                throw new ClientAccountException(ExternalCredentials.PasswordManagedMessage(provider));
            if (!UserPasswordCheck.Verify(user, currentPassword ?? "", _repository, _logger))
                throw new ClientAccountException(WrongPasswordMessage);
            if (UserAdministrationService.ValidatePassword(newPassword) is { } problem)
                throw new ClientAccountException(problem);
            if (newPassword != repeatPassword)
                throw new ClientAccountException("The two new passwords are not the same.");
            if (newPassword == currentPassword)
                throw new ClientAccountException("Choose a password that is not the current one.");

            user = RequireUser(username); // the check can have upgraded an old hash
            user.HashedPassword = PasswordHasher.Hash(newPassword);
            user.PasswordChangedAt = _time.GetUtcNow().UtcDateTime;
            using (_actors.Begin(SelfActor))
            {
                if (!_repository.UpdateUser(user))
                    throw new ClientAccountException("The password could not be saved. Try again.");
            }
            _logger.LogInformation("User {Username} changed the password in the web client.", user.Username);
            return user;
        }

        public IReadOnlyList<PublicKeyEntry> ListPublicKeys(string username) =>
            RequireUser(username).PublicKeys?.ToList() ?? new List<PublicKeyEntry>();

        /// <summary>Adds the keys of an <c>authorized_keys</c> text; returns how many were added and skipped (already there).</summary>
        public (int Added, int Skipped) AddPublicKeys(string username, string text)
        {
            RequireUser(username);
            try
            {
                using (_actors.Begin(SelfActor))
                    return _users.AddPublicKeys(username, text, null, PublicKeySource.SelfService);
            }
            catch (UserAdministrationException ex)
            {
                throw new ClientAccountException(ex.Message);
            }
        }

        public bool RemovePublicKey(string username, string keyBase64)
        {
            RequireUser(username);
            try
            {
                using (_actors.Begin(SelfActor))
                    return _users.RemovePublicKey(username, keyBase64 ?? "");
            }
            catch (UserAdministrationException ex)
            {
                throw new ClientAccountException(ex.Message);
            }
        }

        public IReadOnlyList<AppPassword> ListAppPasswords(string username) =>
            RequireUser(username).AppPasswords?.ToList() ?? new List<AppPassword>();

        /// <summary>Creates an app password; returns it with its secret, which is shown once and not stored.</summary>
        public (AppPassword Entry, string Secret) CreateAppPassword(string username, string name, UserProtocols protocols, DateTime? expiresAtUtc)
        {
            RequireUser(username);
            try
            {
                (AppPassword Entry, string Secret) created;
                using (_actors.Begin(SelfActor))
                    created = _users.CreateAppPassword(username, name, protocols, expiresAtUtc, _time.GetUtcNow().UtcDateTime);
                _logger.LogInformation("User {Username} created the app password {Name} ({Id}) in the web client.",
                    LogText.Clean(username), LogText.Clean(created.Entry.Name), created.Entry.Id);
                return created;
            }
            catch (UserAdministrationException ex)
            {
                throw new ClientAccountException(ex.Message);
            }
        }

        public bool RemoveAppPassword(string username, string id)
        {
            RequireUser(username);
            try
            {
                using (_actors.Begin(SelfActor))
                    return _users.RemoveAppPassword(username, id ?? "");
            }
            catch (UserAdministrationException ex)
            {
                throw new ClientAccountException(ex.Message);
            }
        }

        public Task<TwoFactorStatus> GetTwoFactorStatusAsync(string username, CancellationToken ct) =>
            _twoFactor.GetStatusAsync(Subject(username), ct);

        public async Task<TwoFactorSetup> BeginTwoFactorSetupAsync(string username, CancellationToken ct)
        {
            var user = RequireUser(username);
            try
            {
                return await _twoFactor.BeginSetupAsync(TwoFactorSubject.ForUser(user), user.Username, ct);
            }
            catch (TwoFactorException ex)
            {
                throw new ClientAccountException(ex.Message);
            }
        }

        /// <summary>Turns the second factor on; returns the recovery codes (show them once).</summary>
        public async Task<IReadOnlyList<string>> ConfirmTwoFactorSetupAsync(string username, string code, CancellationToken ct)
        {
            var user = RequireUser(username);
            IReadOnlyList<string> codes;
            try
            {
                codes = await _twoFactor.ConfirmSetupAsync(TwoFactorSubject.ForUser(user), code, ct);
            }
            catch (TwoFactorException ex)
            {
                throw new ClientAccountException(ex.Message);
            }
            if (codes == null)
                throw new ClientAccountException("The code is not valid. Check the time of the device and try the next code.");
            await PublishTwoFactorChangeAsync(user.Username, ct);
            return codes;
        }

        public async Task<IReadOnlyList<string>> RegenerateRecoveryCodesAsync(string username, string currentCode, CancellationToken ct)
        {
            var user = RequireUser(username);
            await DemandCodeAsync(user, currentCode, ct);
            try
            {
                var codes = await _twoFactor.RegenerateRecoveryCodesAsync(TwoFactorSubject.ForUser(user), ct);
                await PublishTwoFactorChangeAsync(user.Username, ct);
                return codes;
            }
            catch (TwoFactorException ex)
            {
                throw new ClientAccountException(ex.Message);
            }
        }

        /// <summary>Turns the second factor off. A confirmed one needs a current code; an unfinished setup does not.</summary>
        public async Task DisableTwoFactorAsync(string username, string currentCode, CancellationToken ct)
        {
            var user = RequireUser(username);
            var subject = TwoFactorSubject.ForUser(user);
            var status = await _twoFactor.GetStatusAsync(subject, ct);
            if (status.State == TwoFactorState.On)
                await DemandCodeAsync(user, currentCode, ct);
            if (await _twoFactor.ResetAsync(subject, ct) && status.State == TwoFactorState.On)
                await PublishTwoFactorChangeAsync(user.Username, ct);
        }

        /// <summary>The open connections of the user, of every protocol, oldest first.</summary>
        public IReadOnlyList<ConnectionInfo> ListSessions(string username) =>
            _connections.GetAll().Where(c => string.Equals(c.Username, username, StringComparison.OrdinalIgnoreCase)).ToList();

        /// <summary>Closes one open connection of the user. False when it is not one of its connections.</summary>
        public async Task<bool> EndSessionAsync(string username, Guid id)
        {
            var connection = _connections.Get(id);
            if (connection == null || !string.Equals(connection.Username, username, StringComparison.OrdinalIgnoreCase))
                return false;
            return await _connections.DisconnectAsync(id, "Closed by the user in the web client.");
        }

        private async Task DemandCodeAsync(User user, string code, CancellationToken ct)
        {
            var check = await _twoFactor.VerifyAsync(TwoFactorSubject.ForUser(user), code, ct);
            if (check is not (TwoFactorCheck.Valid or TwoFactorCheck.RecoveryCode))
                throw new ClientAccountException(check == TwoFactorCheck.LockedOut
                    ? "Too many wrong codes. Try again later."
                    : "Enter a current code of your authenticator app (or a recovery code).");
        }

        private Task PublishTwoFactorChangeAsync(string username, CancellationToken ct) =>
            _events.PublishAsync(new ProviderEvent(ProviderAction.Update, ProviderObjectType.User, username)
            {
                Timestamp = _time.GetUtcNow(),
                Actor = SelfActor,
                ChangedFields = [SshServer.Administration.TwoFactorAdministration.ChangedField],
            }, ct).AsTask();

        private TwoFactorSubject Subject(string username) => TwoFactorSubject.ForUser(RequireUser(username));

        private User RequireUser(string username) =>
            (string.IsNullOrEmpty(username) ? null : _repository.GetUser(username))
            ?? throw new ClientAccountException("Your account does not exist any more.");
    }
}
