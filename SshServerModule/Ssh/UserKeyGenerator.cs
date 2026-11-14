using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using SshServer.Interfaces.Authentication;
using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FxSsh.SshServerModule
{
    /// <summary>A new key pair for a user: the public key entry to store and the private key for the user (never stored).</summary>
    /// <param name="PrivateKey">The private key file: PEM for RSA, the OpenSSH format for ed25519.</param>
    /// <param name="FileExtension">The file name extension for the private key: ".pem" or "" (OpenSSH: id_ed25519).</param>
    public sealed record GeneratedUserKey(PublicKeyEntry PublicKey, string PrivateKey, string FileExtension);

    /// <summary>Makes user key pairs for the admin UI ("Generate"): RSA 4096 (as before issue #58) and ed25519.</summary>
    public static class UserKeyGenerator
    {
        public const int RsaBits = 4096;

        /// <summary>A 4096-bit RSA key; the private key is a PKCS#1 PEM (<c>-----BEGIN RSA PRIVATE KEY-----</c>).</summary>
        public static GeneratedUserKey GenerateRsa(string comment, DateTime addedAtUtc)
        {
            using var rsa = RSA.Create(RsaBits);
            var entry = SshPublicKey.FromRsa(rsa.ExportParameters(false), comment, PublicKeySource.Admin, addedAtUtc);
            return new GeneratedUserKey(entry, rsa.ExportRSAPrivateKeyPem() + "\n", ".pem");
        }

        /// <summary>An ed25519 key; the private key is in the OpenSSH format (<c>-----BEGIN OPENSSH PRIVATE KEY-----</c>), unencrypted.</summary>
        public static GeneratedUserKey GenerateEd25519(string comment, DateTime addedAtUtc)
        {
            var privateKey = new byte[Ed25519.SecretKeySize];
            var publicKey = new byte[Ed25519.PublicKeySize];
            Ed25519.GeneratePrivateKey(new SecureRandom(), privateKey);
            Ed25519.GeneratePublicKey(privateKey, 0, publicKey, 0);
            try
            {
                var blob = Ed25519Blob(publicKey);
                var entry = SshPublicKey.FromBlob(blob, comment, PublicKeySource.Admin, addedAtUtc);
                return new GeneratedUserKey(entry, OpenSshEd25519PrivateKey(privateKey, publicKey, comment ?? string.Empty), string.Empty);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }

        /// <summary>The <c>ssh-ed25519</c> key blob of a 32-byte public key (RFC 8709 section 4).</summary>
        internal static byte[] Ed25519Blob(byte[] publicKey)
        {
            using var stream = new MemoryStream();
            WriteString(stream, Encoding.ASCII.GetBytes(SshPublicKey.Ed25519));
            WriteString(stream, publicKey);
            return stream.ToArray();
        }

        /// <summary>
        /// The OpenSSH private key format "openssh-key-v1" without encryption (PROTOCOL.key in the OpenSSH sources):
        /// the public key, then a private section with two equal check numbers, the key type, the public key, the
        /// private key (seed and public key, 64 bytes), the comment and padding 1, 2, 3, ... to a multiple of 8.
        /// </summary>
        internal static string OpenSshEd25519PrivateKey(byte[] privateKey, byte[] publicKey, string comment)
        {
            var publicBlob = Ed25519Blob(publicKey);

            using var section = new MemoryStream();
            var check = new byte[4];
            RandomNumberGenerator.Fill(check);
            section.Write(check);
            section.Write(check);
            WriteString(section, Encoding.ASCII.GetBytes(SshPublicKey.Ed25519));
            WriteString(section, publicKey);
            var secret = new byte[privateKey.Length + publicKey.Length];
            privateKey.CopyTo(secret, 0);
            publicKey.CopyTo(secret, privateKey.Length);
            WriteString(section, secret);
            CryptographicOperations.ZeroMemory(secret);
            WriteString(section, Encoding.UTF8.GetBytes(comment));
            for (byte pad = 1; section.Length % 8 != 0; pad++)
                section.WriteByte(pad);

            using var file = new MemoryStream();
            file.Write(Encoding.ASCII.GetBytes("openssh-key-v1\0"));
            WriteString(file, Encoding.ASCII.GetBytes("none")); // cipher
            WriteString(file, Encoding.ASCII.GetBytes("none")); // kdf
            WriteString(file, Array.Empty<byte>());              // kdf options
            var count = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(count, 1);
            file.Write(count);
            WriteString(file, publicBlob);
            var sectionBytes = section.ToArray();
            WriteString(file, sectionBytes);
            CryptographicOperations.ZeroMemory(sectionBytes);

            var base64 = Convert.ToBase64String(file.ToArray());
            var text = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
            for (var i = 0; i < base64.Length; i += 70)
                text.Append(base64, i, Math.Min(70, base64.Length - i)).Append('\n');
            text.Append("-----END OPENSSH PRIVATE KEY-----\n");
            return text.ToString();
        }

        private static void WriteString(Stream stream, byte[] value)
        {
            var length = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(length, (uint)value.Length);
            stream.Write(length);
            stream.Write(value);
        }
    }
}
