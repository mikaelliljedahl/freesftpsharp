using SshServer.Interfaces;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace FxSsh.SshServerModule
{
    /// <summary>
    /// The server host keys.
    /// <list type="bullet">
    /// <item>RSA: <see cref="ServerSettings.ServerRsaKey"/>, a base64 CSP blob with the private key (the format
    /// that older versions created) or a PEM private key. It is registered as rsa-sha2-512 and rsa-sha2-256.
    /// ssh-rsa (SHA-1 signatures) is not offered.</item>
    /// <item>ECDSA P-256: <see cref="ServerSettings.ServerEcdsaKey"/>, a PKCS#8 PEM private key. When it is
    /// empty (for example in a config.db made by an older version), a new key is made and saved.</item>
    /// </list>
    /// </summary>
    internal static class HostKeys
    {
        internal readonly record struct HostKey(string Algorithm, string Pem);

        internal static IReadOnlyList<HostKey> Load(ISettingsRepository repository)
        {
            var settings = repository.ServerSettings;
            if (string.IsNullOrWhiteSpace(settings.ServerEcdsaKey))
            {
                settings.ServerEcdsaKey = KeyGenerator.GenerateECDsaKeyPem("nistp256");
                repository.UpdateServerSettings(settings);
            }

            var rsaPem = RsaKeyToPem(settings.ServerRsaKey);
            ValidateEcdsaPem(settings.ServerEcdsaKey);

            return new[]
            {
                new HostKey("ecdsa-sha2-nistp256", settings.ServerEcdsaKey),
                new HostKey("rsa-sha2-512", rsaPem),
                new HostKey("rsa-sha2-256", rsaPem),
            };
        }

        /// <summary>Converts the stored RSA host key (base64 CSP blob or PEM) to a PKCS#8 PEM private key.</summary>
        internal static string RsaKeyToPem(string storedKey)
        {
            if (string.IsNullOrWhiteSpace(storedKey))
                throw new InvalidOperationException("The server settings have no RSA host key (ServerRsaKey).");

            using var rsa = RSA.Create();
            var trimmed = storedKey.Trim();
            if (trimmed.StartsWith("-----BEGIN", StringComparison.Ordinal))
            {
                rsa.ImportFromPem(trimmed);
            }
            else
            {
                using var csp = new RSACryptoServiceProvider();
                csp.ImportCspBlob(Convert.FromBase64String(trimmed));
                if (csp.PublicOnly)
                    throw new InvalidOperationException("The RSA host key (ServerRsaKey) has no private key.");
                rsa.ImportParameters(csp.ExportParameters(true));
            }
            return rsa.ExportPkcs8PrivateKeyPem();
        }

        private static void ValidateEcdsaPem(string pem)
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);
            if (ecdsa.KeySize != 256)
                throw new InvalidOperationException("The ECDSA host key (ServerEcdsaKey) must be a P-256 key.");
        }
    }
}
