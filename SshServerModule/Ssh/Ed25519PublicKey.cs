using FxSsh.Algorithms;
using Org.BouncyCastle.Math.EC.Rfc8032;
using System;
using System.Security.Cryptography;
using System.Text;

namespace FxSsh.SshServerModule
{
    /// <summary>
    /// The <c>ssh-ed25519</c> public key algorithm (RFC 8709) for user public key authentication. FxSsh has no ed25519,
    /// and .NET has no ed25519 signatures, so the signature check uses BouncyCastle. The server registers it in its
    /// algorithm catalog (<see cref="Register"/>). It only verifies: the server has no ed25519 host key, so it never
    /// offers ssh-ed25519 as a host key algorithm.
    /// </summary>
    internal sealed class Ed25519PublicKey : PublicKeyAlgorithm
    {
        public const string AlgorithmName = "ssh-ed25519";

        private byte[] _publicKey;

        public Ed25519PublicKey() : base(null)
        {
        }

        public override string Name => AlgorithmName;

        /// <summary>Adds ssh-ed25519 to the public key algorithms of a server (also announced in server-sig-algs).</summary>
        public static void Register(FxSsh.SshServer server) =>
            server.Algorithms.ConfigureHazmat(catalog => catalog.HostKeyCollection.Add(AlgorithmName, _ => new Ed25519PublicKey()));

        public override void ImportKey(string key) =>
            throw new NotSupportedException("ssh-ed25519 is only used to verify user keys.");

        public override string ExportKey() =>
            throw new NotSupportedException("ssh-ed25519 is only used to verify user keys.");

        public override void LoadKeyAndCertificatesData(byte[] data)
        {
            var reader = new SshDataReader(data);
            if (reader.ReadString(Encoding.ASCII) != AlgorithmName)
                throw new CryptographicException("The key is not an ssh-ed25519 key.");
            var key = reader.ReadBinary();
            if (key.Length != Ed25519.PublicKeySize || reader.DataAvailable != 0)
                throw new CryptographicException("The ssh-ed25519 key does not have 32 bytes.");
            _publicKey = key;
        }

        public override byte[] CreateKeyAndCertificatesData()
        {
            if (_publicKey == null)
                throw new InvalidOperationException("No key is loaded.");
            using var writer = new SshDataWriter();
            return writer
                .Write(AlgorithmName, Encoding.ASCII)
                .WriteBinary(_publicKey)
                .ToByteArray();
        }

        /// <param name="signature">The raw 64-byte signature (without the SSH signature framing).</param>
        public override bool VerifyData(byte[] data, byte[] signature)
        {
            if (_publicKey == null || data == null || signature == null || signature.Length != Ed25519.SignatureSize)
                return false;
            try
            {
                return Ed25519.Verify(signature, 0, _publicKey, 0, data, 0, data.Length);
            }
            catch (ArgumentException)
            {
                return false; // an invalid point
            }
        }

        public override bool VerifyHash(byte[] hash, byte[] signature) =>
            throw new NotSupportedException("ssh-ed25519 signs the data, not a hash.");

        public override byte[] SignData(byte[] data) =>
            throw new NotSupportedException("ssh-ed25519 is only used to verify user keys.");

        public override byte[] SignHash(byte[] hash) =>
            throw new NotSupportedException("ssh-ed25519 is only used to verify user keys.");
    }
}
