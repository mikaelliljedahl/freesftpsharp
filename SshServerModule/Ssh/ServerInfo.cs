using FxSsh.Algorithms;
using FxSsh.Algorithms.Catalog;
using SshServer.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace FxSsh.SshServerModule
{
    /// <summary>A host key of the server as the admin UI shows it: never the private key, only the fingerprint.</summary>
    /// <param name="KeyType">"ECDSA" or "RSA".</param>
    /// <param name="Algorithms">The host key algorithms that use the key, for example rsa-sha2-512 and rsa-sha2-256.</param>
    /// <param name="KeySize">The key size in bits, 0 when the key cannot be read.</param>
    /// <param name="Fingerprint">"SHA256:..." as OpenSSH shows it (base64 without padding). Null when the key cannot be read.</param>
    /// <param name="Error">Why the key cannot be read, or null.</param>
    public sealed record HostKeyFingerprint(string KeyType, IReadOnlyList<string> Algorithms, int KeySize, string Fingerprint, string Error);

    /// <summary>The algorithms the server offers in its KEXINIT, in preference order.</summary>
    public sealed record ServerAlgorithms(
        IReadOnlyList<string> HostKey, IReadOnlyList<string> KeyExchange, IReadOnlyList<string> Encryption,
        IReadOnlyList<string> Mac, IReadOnlyList<string> Compression);

    /// <summary>Read-only information about the server for the admin UI: host key fingerprints and algorithms.</summary>
    public static class ServerInfo
    {
        private const string EcdsaAlgorithm = "ecdsa-sha2-nistp256";
        private static readonly string[] RsaAlgorithms = { "rsa-sha2-512", "rsa-sha2-256" };

        /// <summary>The fingerprints of the stored host keys (<see cref="ServerSettings.ServerEcdsaKey"/>, <see cref="ServerSettings.ServerRsaKey"/>).</summary>
        public static IReadOnlyList<HostKeyFingerprint> GetHostKeyFingerprints(ServerSettings settings)
        {
            ArgumentNullException.ThrowIfNull(settings);
            return new[]
            {
                Describe("ECDSA", new[] { EcdsaAlgorithm }, settings.ServerEcdsaKey,
                    "No ECDSA host key is stored yet. The server makes one at the next start.",
                    pem =>
                    {
                        var key = new EcdsaKey("nistp256", pem);
                        return (256, key.GetFingerprint());
                    }),
                Describe("RSA", RsaAlgorithms, settings.ServerRsaKey,
                    "No RSA host key is stored.",
                    stored =>
                    {
                        var pem = HostKeys.RsaKeyToPem(stored);
                        using var rsa = RSA.Create();
                        rsa.ImportFromPem(pem);
                        var key = new RsaKey(256, pem);
                        return (rsa.KeySize, key.GetFingerprint());
                    }),
            };
        }

        /// <summary>The algorithms of the server. The server uses the default FxSsh catalog; host keys are the ones it registers.</summary>
        public static ServerAlgorithms GetAlgorithms()
        {
            var catalog = new AlgorithmCatalog();
            var registered = new[] { EcdsaAlgorithm }.Concat(RsaAlgorithms).ToHashSet(StringComparer.Ordinal);
            return new ServerAlgorithms(
                catalog.HostKeyCollection.NegotiableNames.Where(registered.Contains).ToList(),
                catalog.KeyExchangeCollection.NegotiableNames.ToList(),
                catalog.EncryptionCollection.NegotiableNames.ToList(),
                catalog.HmacCollection.NegotiableNames.ToList(),
                catalog.CompressionCollection.NegotiableNames.ToList());
        }

        /// <summary>"SHA256:..." of a user public key (<see cref="User.RsaPublicKey"/>, a base64 CSP blob). Null when it is empty or invalid.</summary>
        public static string GetUserKeyFingerprint(string base64CspBlob)
        {
            if (string.IsNullOrWhiteSpace(base64CspBlob))
                return null;
            try
            {
                return "SHA256:" + UserLogics.GetRsaPublicKeyFingerprint(base64CspBlob).TrimEnd('=');
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
            {
                return null;
            }
        }

        private static HostKeyFingerprint Describe(string keyType, IReadOnlyList<string> algorithms, string stored, string missing,
            Func<string, (int KeySize, string Fingerprint)> read)
        {
            if (string.IsNullOrWhiteSpace(stored))
                return new HostKeyFingerprint(keyType, algorithms, 0, null, missing);
            try
            {
                var (size, fingerprint) = read(stored);
                return new HostKeyFingerprint(keyType, algorithms, size, "SHA256:" + fingerprint.TrimEnd('='), null);
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException or InvalidOperationException)
            {
                return new HostKeyFingerprint(keyType, algorithms, 0, null, $"The stored {keyType} host key cannot be read: {ex.Message}");
            }
        }
    }
}
