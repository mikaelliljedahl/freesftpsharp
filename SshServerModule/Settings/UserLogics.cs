using SshServer.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Net;

namespace FxSsh.SshServerModule
{


    internal static class UserLogics
    {

        /// <summary>
        /// True when the client may log in from its address: <paramref name="allowedIps"/> are the effective allowed
        /// networks of the user (<see cref="SshServer.Interfaces.Users.EffectiveUserSettings.AllowedIps"/>: its IP
        /// whitelist or the networks of its groups). An empty list allows every address.
        /// </summary>
        internal static bool VerifyUserIpWhitelisted(IReadOnlyList<string> allowedIps, EndPoint remoteEndpoint)
        {
            if (allowedIps == null || allowedIps.Count == 0) // No check needed
                return true;

            if (remoteEndpoint is not IPEndPoint endpoint)
                return false;

            // CIDR entries or single addresses. The server listens dual-stack, so an IPv4 client has an address such
            // as ::ffff:192.168.1.5; CidrNotation matches it as IPv4. Invalid entries are skipped.
            return CidrNotation.Contains(CidrNotation.ParseValid(allowedIps), endpoint.Address);
        }

        /// <summary>
        /// Public key authentication (issue #58): true when <paramref name="keyBlob"/>, the SSH public key blob of the
        /// login request (<c>UserAuthArgs.Key</c>), is the whole blob of one of the user's keys that is not expired at
        /// <paramref name="utcNow"/>. The fingerprint is never compared: a key with the same fingerprint prefix but
        /// another blob is refused.
        /// </summary>
        internal static bool VerifyUserKey(User user, byte[] keyBlob, DateTime utcNow)
        {
            if (user?.PublicKeys == null || keyBlob == null || keyBlob.Length == 0)
                return false;

            var match = false;
            foreach (var entry in user.PublicKeys)
            {
                if (entry == null)
                    continue;
                // Every entry is compared (no early exit), so the time does not tell which entry matched.
                if (entry.Matches(keyBlob) && !entry.IsExpired(utcNow))
                    match = true;
            }
            return match;
        }

        /// <summary>
        /// Checks a password against <see cref="User.HashedPassword"/>. A PBKDF2 hash is checked with
        /// <see cref="PasswordHasher.Verify"/>. An old unsalted SHA-256 hash (before issue #23) is checked in constant
        /// time; on success the user is saved with a new PBKDF2 hash, so the old hash is used only once.
        /// Every failed check costs the same key derivation as a real one, so the response time does not tell
        /// which format a user has or whether the user has a password.
        /// </summary>
        internal static bool VerifyUserPassword(User user, string password, ISettingsRepository repository, ILogger logger)
        {
            var stored = user?.HashedPassword;

            if (PasswordHasher.IsWellFormed(stored))
                return PasswordHasher.Verify(password, stored);

            if (PasswordHasher.IsLegacySha256(stored) && PasswordHasher.VerifyLegacySha256(password, stored))
            {
                user.HashedPassword = PasswordHasher.Hash(password);
                if (repository.UpdateUser(user))
                    logger.LogInformation("Upgraded the password hash of user {Username} from SHA-256 to {Algorithm}.",
                        user.Username, PasswordHasher.Algorithm);
                else
                    logger.LogWarning("Could not save the upgraded password hash of user {Username}.", user.Username);
                return true;
            }

            SimulatePasswordCheck();
            return false;
        }

        /// <summary>
        /// Does the work of one password check without a result. Call it for a login with an unknown user name, so
        /// that the response time does not tell whether the user exists.
        /// </summary>
        internal static void SimulatePasswordCheck() => PasswordHasher.BurnEquivalentWork();
    }
}