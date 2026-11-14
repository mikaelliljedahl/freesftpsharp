using System.Security.Cryptography;
using System.Text;
using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.Infrastructure;

/// <summary>
/// Credentials and keys for the in-process test server.
/// </summary>
public static class TestCredentials
{
    public const string Username = "test_person";
    // Must not be a substring of a GUID or a hex string (tests assert that it is never logged or sent), so it has a non-hex letter and punctuation.
    public const string Password = "pw-Secret!xyz";

    private static readonly Lazy<string> SharedHostKey = new(() => CreateRsaHostKey(2048));

    /// <summary>
    /// Creates the value for <c>User.HashedPassword</c>. This is the ONLY place in the tests that knows
    /// the hash formats. The current format is the salted PBKDF2-SHA256 hash of
    /// <c>SshServer.Interfaces.Security.PasswordHasher</c> (issue #23). The tests use the minimum iteration
    /// count to stay fast; the server makes new hashes with the default count.
    /// </summary>
    public static string HashPassword(string password)
    {
        return PasswordHasher.Hash(password, PasswordHasher.MinimumIterations);
    }

    /// <summary>
    /// The old, unsalted format from before issue #23: base64(SHA-256(ASCII(password))). Old databases still
    /// contain it; the server accepts it once and then stores a PBKDF2 hash.
    /// </summary>
    public static string LegacySha256Hash(string password)
    {
        return Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(password)));
    }

    /// <summary>
    /// An RSA host key in the format of <c>ServerSettings.ServerRsaKey</c>, made the same way as the
    /// LiteDB SettingsRepository makes it (a base64 CSP blob with the private key). All fixtures share one
    /// key, because generating a key takes time.
    /// </summary>
    public static string HostKey => SharedHostKey.Value;

    public static string CreateRsaHostKey(int keySize)
    {
        using var csp = new RSACryptoServiceProvider(keySize);
        return Convert.ToBase64String(csp.ExportCspBlob(true));
    }
}
