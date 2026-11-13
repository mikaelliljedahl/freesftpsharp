using SshServer.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;

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

            // The server listens dual-stack, so an IPv4 client has an address such as ::ffff:192.168.1.5.
            var ipaddress = endpoint.Address.IsIPv4MappedToIPv6 ? endpoint.Address.MapToIPv4() : endpoint.Address;

            foreach(var whitelisted in user.WhitelistedIps)
            {
                IPNetwork ipnetwork = IPNetwork.Parse(whitelisted); // whitelisted must contain  CIDR e.g. /16
                var success = ipnetwork.Contains(ipaddress);
                if (success)
                    return true;
            }

            return false;
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

        internal static bool VerifyUserPassword(User user, string password)
        {
            if (password == null || string.IsNullOrEmpty(user.HashedPassword))
                return false;

            var sha256 = new SHA256CryptoServiceProvider();
            var pwhashed = sha256.ComputeHash(System.Text.Encoding.ASCII.GetBytes(password));
            var base64encoded = Convert.ToBase64String(pwhashed);

            //var testpw = "A6xnQhbz4Vx2HuGl4lXwZ5U2I8iziLRFnhP5eNfIRvQ="; // "1234"

            if (base64encoded == user.HashedPassword)
                return true;
            else
                return false;
        }
    }
}