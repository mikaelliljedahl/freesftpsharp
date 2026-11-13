using System.Security.Cryptography;
using System.Text;

namespace FreeSftpSharp.Tests.Infrastructure;

/// <summary>
/// Credentials and keys for the in-process test server.
/// </summary>
public static class TestCredentials
{
    public const string Username = "test_person";
    public const string Password = "1234";

    private static readonly Lazy<string> SharedHostKey = new(() => CreateRsaHostKey(2048));

    /// <summary>
    /// Creates the value for <c>User.HashedPassword</c>. This is the ONLY place in the tests that knows
    /// the hash format. It must match <c>UserLogics.VerifyUserPassword</c> in SshServerModule:
    /// today that is base64(SHA-256(ASCII(password))). Change it here when the format changes (issue #23).
    /// </summary>
    public static string HashPassword(string password)
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
