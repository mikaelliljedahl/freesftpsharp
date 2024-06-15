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

        internal static bool VerifyUserPassword(User user, string password)
        {
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