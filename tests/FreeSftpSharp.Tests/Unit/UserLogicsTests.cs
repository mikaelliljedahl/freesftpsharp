using System.Net;
using System.Security.Cryptography;
using System.Text;
using FxSsh.SshServerModule;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>
/// <see cref="UserLogics"/>: public key authentication by fingerprint, password check and the IP whitelist.
/// </summary>
public sealed class UserLogicsTests
{
    [Fact]
    public void Fingerprint_of_a_stored_key_is_the_sha256_of_the_ssh_public_key_blob()
    {
        using var rsa = new RSACryptoServiceProvider(2048);
        var stored = Convert.ToBase64String(rsa.ExportCspBlob(false));

        var fingerprint = UserLogics.GetRsaPublicKeyFingerprint(stored);

        Assert.Equal(ExpectedFingerprint(rsa.ExportParameters(false)), fingerprint);
    }

    [Fact]
    public void The_key_of_the_user_is_accepted()
    {
        using var rsa = new RSACryptoServiceProvider(2048);
        var user = new User { Username = "u", RsaPublicKey = Convert.ToBase64String(rsa.ExportCspBlob(false)) };

        Assert.True(UserLogics.VerifyUserKey(user, ExpectedFingerprint(rsa.ExportParameters(false))));
    }

    [Fact]
    public void Another_key_is_rejected()
    {
        using var userKey = new RSACryptoServiceProvider(2048);
        using var otherKey = new RSACryptoServiceProvider(2048);
        var user = new User { Username = "u", RsaPublicKey = Convert.ToBase64String(userKey.ExportCspBlob(false)) };

        Assert.False(UserLogics.VerifyUserKey(user, ExpectedFingerprint(otherKey.ExportParameters(false))));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not base64!")]
    public void A_user_without_a_valid_key_is_rejected(string? storedKey)
    {
        using var rsa = new RSACryptoServiceProvider(2048);
        var user = new User { Username = "u", RsaPublicKey = storedKey! };

        Assert.False(UserLogics.VerifyUserKey(user, ExpectedFingerprint(rsa.ExportParameters(false))));
    }

    [Fact]
    public void Password_check_accepts_the_right_password_and_rejects_others()
    {
        var user = new User { Username = "u", HashedPassword = Infrastructure.TestCredentials.HashPassword("1234") };

        Assert.True(UserLogics.VerifyUserPassword(user, "1234"));
        Assert.False(UserLogics.VerifyUserPassword(user, "12345"));
        Assert.False(UserLogics.VerifyUserPassword(user, ""));
        Assert.False(UserLogics.VerifyUserPassword(new User { Username = "nopw" }, ""));
    }

    [Theory]
    [InlineData("192.168.1.5", true)]
    [InlineData("::ffff:192.168.1.5", true)]   // an IPv4 client on the dual-stack listener
    [InlineData("10.0.0.1", false)]
    [InlineData("::ffff:10.0.0.1", false)]
    public void Ip_whitelist_is_checked_for_ipv4_and_ipv4_mapped_addresses(string address, bool allowed)
    {
        var user = new User
        {
            Username = "u",
            OnlyWhitelistedIps = true,
            WhitelistedIps = new List<string> { "192.168.0.0/16" },
        };

        Assert.Equal(allowed, UserLogics.VerifyUserIpWhitelisted(user, new IPEndPoint(IPAddress.Parse(address), 50000)));
    }

    [Fact]
    public void Without_a_whitelist_every_address_is_allowed()
    {
        var user = new User { Username = "u", OnlyWhitelistedIps = false };

        Assert.True(UserLogics.VerifyUserIpWhitelisted(user, new IPEndPoint(IPAddress.Parse("10.0.0.1"), 50000)));
    }

    /// <summary>base64(SHA-256("ssh-rsa" public key blob)), RFC 4253 section 6.6, made without FxSsh.</summary>
    private static string ExpectedFingerprint(RSAParameters parameters)
    {
        using var blob = new MemoryStream();
        WriteString(blob, Encoding.ASCII.GetBytes("ssh-rsa"));
        WriteString(blob, Mpint(parameters.Exponent!));
        WriteString(blob, Mpint(parameters.Modulus!));
        return Convert.ToBase64String(SHA256.HashData(blob.ToArray()));
    }

    private static byte[] Mpint(byte[] unsignedBigEndian)
    {
        var value = unsignedBigEndian.SkipWhile(b => b == 0).ToArray();
        return value.Length > 0 && (value[0] & 0x80) != 0 ? new byte[] { 0 }.Concat(value).ToArray() : value;
    }

    private static void WriteString(Stream stream, byte[] data)
    {
        stream.Write(new[] { (byte)(data.Length >> 24), (byte)(data.Length >> 16), (byte)(data.Length >> 8), (byte)data.Length });
        stream.Write(data);
    }
}
