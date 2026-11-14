using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.SshServerModule;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Net;
using SshServer.Interfaces.Users;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// Checks the user name and password of a web client login with the rules of the SSH login: the lifecycle
    /// (<see cref="UserLoginRules"/>: status, expiry, session limit), the allowed networks and methods of the user and its
    /// groups (<see cref="IEffectiveUserSettingsService"/>), and the stored password. A refusal costs the time of a
    /// password check. An expired password is accepted with <see cref="ClientCredentialResult.PasswordExpired"/>: the user
    /// can only set a new password then (the SSH login refuses it, because SSH has no way to change it).
    /// </summary>
    public sealed class PasswordCredentialVerifier : IClientCredentialVerifier
    {
        private readonly ISettingsRepository _repository;
        private readonly IEffectiveUserSettingsService _settings;
        private readonly IConnectionRegistry _connections;
        private readonly TimeProvider _time;
        private readonly ILogger<PasswordCredentialVerifier> _logger;

        public PasswordCredentialVerifier(ISettingsRepository repository, IEffectiveUserSettingsService settings, IConnectionRegistry connections,
            TimeProvider time, ILogger<PasswordCredentialVerifier> logger)
        {
            _repository = repository;
            _settings = settings;
            _connections = connections;
            _time = time;
            _logger = logger;
        }

        public Task<ClientCredentialResult> VerifyAsync(string username, string password, IPAddress client, CancellationToken ct)
        {
            // The checks are synchronous (the repository and the hash); the page runs them on its request thread.
            return Task.FromResult(Verify(username?.Trim(), password ?? string.Empty, client));
        }

        private ClientCredentialResult Verify(string username, string password, IPAddress client)
        {
            var user = string.IsNullOrEmpty(username) ? null : _repository.GetUser(username);
            if (user == null)
                return Refuse("unknown user");

            var now = _time.GetUtcNow().UtcDateTime;
            var maxAge = _repository.ServerSettings.PasswordMaxAgeDays;
            var expired = UserLoginRules.IsPasswordExpired(user, now, maxAge);
            // With an expired password the user may log in to change it: the age is checked by the caller (0 = no age check).
            var refusal = UserLoginRules.Refusal(user, AuthMethods.Password, now, expired ? 0 : maxAge)
                          ?? UserLoginRules.SessionLimitRefusal(user, _connections.CountSessions(user.Username, Guid.Empty));
            if (refusal != null)
                return Refuse(refusal);

            var settings = _settings.Resolve(user);
            if (settings.AllowedIps.Count > 0
                && (client == null || !CidrNotation.Contains(CidrNotation.ParseValid(settings.AllowedIps), client)))
            {
                return Refuse("the address is not in the whitelist of the user");
            }
            if ((settings.AllowedAuthMethods & AuthMethods.Password) == 0)
                return Refuse("the password method is not allowed for the user");
            // A browser has no SSH key: a login that needs a key as one of its steps is refused.
            if (user.RequireAllOf is { Count: > 0 } steps && steps.Any(s => s == AuthMethods.PublicKey))
                return Refuse("the login of the user needs a public key");

            if (!UserPasswordCheck.Verify(user, password, _repository, _logger))
                return ClientCredentialResult.Refused("wrong password");

            return new ClientCredentialResult(user, null, expired);
        }

        private static ClientCredentialResult Refuse(string reason)
        {
            UserPasswordCheck.Simulate(); // the same time as a wrong password
            return ClientCredentialResult.Refused(reason);
        }
    }
}
