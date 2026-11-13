using SshServer.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Security;

namespace FxSsh.SshServerModule
{


    internal static class UserLogics
    {

        internal static bool VerifyUserIpWhitelisted(User user, EndPoint remoteEndpoint)
        {
            if (!user.OnlyWhitelistedIps || user.WhitelistedIps == null || user.WhitelistedIps.Count == 0) // No check needed
                return true;

            var endpoint = remoteEndpoint as IPEndPoint;

            // https://github.com/lduchosal/ipnetwork
            var ipaddress = IPAddress.Parse(endpoint.Address.ToString());

            foreach(var whitelisted in user.WhitelistedIps)
            {
                IPNetwork ipnetwork = IPNetwork.Parse(whitelisted); // whitelisted must contain  CIDR e.g. /16
                var success = ipnetwork.Contains(ipaddress);
                if (success)
                    return true;
            }

            return false;
        }

        internal static bool VerifyUserKey(User user, byte[] key, string fingerprint, string keyAlgorithm)
        {
            var savedkey = Convert.FromBase64String(user.RsaPublicKey);
            var keyAlg = new Algorithms.RsaKey(null);            
            keyAlg.ImportKey(savedkey);
            var fingprint2 = keyAlg.GetFingerprint();

            return fingerprint == fingprint2;

        }

        internal static byte[] ConvertFingerprintToByteArray(string fingerprint)
        {
            return fingerprint.Split(':').Select(s => Convert.ToByte(s, 16)).ToArray();
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