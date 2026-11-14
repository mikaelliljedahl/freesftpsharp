using System.Security.Cryptography;
using FxSsh.SshServerModule;
using Renci.SshNet;
using SshServer.Interfaces.Authentication;

namespace FreeSftpSharp.Tests.Infrastructure;

/// <summary>A user key pair for the tests: the entry the server stores and the private key file for the client.</summary>
/// <param name="PrivateKey">The private key file: OpenSSH format (ed25519) or PEM (RSA, ECDSA). SSH.NET and OpenSSH read both.</param>
public sealed record TestUserKey(PublicKeyEntry Entry, string PrivateKey)
{
    public string AuthorizedKeysLine => SshPublicKey.ToAuthorizedKeysLine(Entry);

    public byte[] Blob => Convert.FromBase64String(Entry.KeyBase64);

    /// <summary>The key for SSH.NET.</summary>
    public PrivateKeyFile ToPrivateKeyFile() => new(new MemoryStream(System.Text.Encoding.ASCII.GetBytes(PrivateKey)));

    /// <summary>Writes the private key to a file that only the owner can read (OpenSSH refuses other files).</summary>
    public string WriteTo(string directory)
    {
        var path = Path.Combine(directory, "key-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(path, PrivateKey);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return path;
    }
}

/// <summary>Makes user key pairs. Ed25519 and RSA use the generator of the admin UI.</summary>
public static class TestUserKeys
{
    public static TestUserKey Ed25519(string comment = "test@ed25519")
    {
        var key = UserKeyGenerator.GenerateEd25519(comment, DateTime.UtcNow);
        return new TestUserKey(key.PublicKey, key.PrivateKey);
    }

    /// <summary>An RSA key (2048 bits: faster than the 4096 bits of the admin UI).</summary>
    public static TestUserKey Rsa(string comment = "test@rsa")
    {
        using var rsa = RSA.Create(2048);
        var entry = SshPublicKey.FromRsa(rsa.ExportParameters(false), comment, PublicKeySource.Admin, DateTime.UtcNow);
        return new TestUserKey(entry, rsa.ExportRSAPrivateKeyPem() + "\n");
    }

    public static TestUserKey EcdsaNistP256(string comment = "test@ecdsa")
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var entry = SshPublicKey.Parse(ecdsa.ExportSubjectPublicKeyInfoPem(), PublicKeySource.Admin, DateTime.UtcNow);
        entry.Comment = comment;
        return new TestUserKey(entry, ecdsa.ExportECPrivateKeyPem() + "\n");
    }
}
