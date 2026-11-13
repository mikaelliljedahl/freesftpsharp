using SshServer.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Net;

namespace FxSsh.SshServerModule
{


    internal static class UserLogics
    {

        internal static bool VerifyUserIpWhitelisted(User user, EndPoint remoteEndpoint)
        {
            if (!user.OnlyWhitelistedIps || user.WhitelistedIps == null || user.WhitelistedIps.Count == 0) // No check needed
                return true;

            if (remoteEndpoint is not IPEndPoint endpoint)
                return false;

            // CIDR entries or single addresses. The server listens dual-stack, so an IPv4 client has an address such
            // as ::ffff:192.168.1.5; CidrNotation matches it as IPv4. Invalid entries are skipped.
            return CidrNotation.Contains(CidrNotation.ParseValid(user.WhitelistedIps), endpoint.Address);
        }

        /// <summary>
        /// Public key authentication by fingerprint. <see cref="User.RsaPublicKey"/> is a base64 CSP blob
        /// (made by the admin UI). The fingerprint is the base64 SHA-256 of the SSH public key blob, as FxSsh
        /// gives it in <c>UserAuthArgs.Fingerprint</c> (OpenSSH shows it as "SHA256:...", without padding).
        /// </summary>
        internal static bool VerifyUserKey(User user, string fingerprint)
        {
            if (string.IsNullOrWhiteSpace(user.RsaPublicKey) || string.IsNullOrEmpty(fingerprint))
                return false;

            string savedFingerprint;
            try
            {
                savedFingerprint = GetRsaPublicKeyFingerprint(user.RsaPublicKey);
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException)
            {
                return false;
            }

            return string.Equals(fingerprint, savedFingerprint, StringComparison.Ordinal);
        }

        /// <summary>The base64 SHA-256 fingerprint of an RSA public key that is stored as a base64 CSP blob.</summary>
        internal static string GetRsaPublicKeyFingerprint(string base64CspBlob)
        {
            using var csp = new RSACryptoServiceProvider();
            csp.ImportCspBlob(Convert.FromBase64String(base64CspBlob));
            var key = new FxSsh.Algorithms.RsaKey(256, csp.ExportSubjectPublicKeyInfoPem());
            return key.GetFingerprint();
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