using System.Security.Cryptography;
using System.Text;
using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet;
using Renci.SshNet.Common;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// Public key authentication (the user's RSA public key is stored as a base64 CSP blob and checked by its
/// SHA-256 fingerprint) and the per-user IP whitelist, with SSH.NET.
/// </summary>
public sealed class PublicKeyAndWhitelistTests : IClassFixture<SftpServerFixture>
{
    private readonly SftpServerFixture _server;

    public PublicKeyAndWhitelistTests(SftpServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public void Public_key_of_the_user_is_accepted()
    {
        using var key = new RSACryptoServiceProvider(2048);
        var username = AddUser(publicKey: key);

        using var client = CreateKeyClient(username, key);
        client.Connect();

        Assert.True(client.IsConnected);
        Assert.Equal("/", client.WorkingDirectory);
    }

    [Fact]
    public void Another_public_key_is_rejected()
    {
        using var userKey = new RSACryptoServiceProvider(2048);
        using var otherKey = new RSACryptoServiceProvider(2048);
        var username = AddUser(publicKey: userKey);

        using var client = CreateKeyClient(username, otherKey);

        Assert.Throws<SshAuthenticationException>(() => client.Connect());
    }

    [Fact]
    public void Public_key_is_rejected_for_a_user_without_a_key()
    {
        using var key = new RSACryptoServiceProvider(2048);
        var username = AddUser(publicKey: null);

        using var client = CreateKeyClient(username, key);

        Assert.Throws<SshAuthenticationException>(() => client.Connect());
    }

    [Fact]
    public void Unknown_user_is_rejected()
    {
        using var client = new SftpClient(SftpServerFixture.Host, _server.Port, "nobody-" + Guid.NewGuid().ToString("N"), "1234");
        client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(15);

        Assert.Throws<SshAuthenticationException>(() => client.Connect());
    }

    [Fact]
    public void Client_inside_the_ip_whitelist_can_log_in()
    {
        var username = AddUser(publicKey: null, whitelist: new List<string> { "127.0.0.0/8" });

        using var client = CreatePasswordClient(username);
        client.Connect();

        Assert.True(client.IsConnected);
    }

    [Fact]
    public void Client_outside_the_ip_whitelist_is_rejected_even_with_the_right_password()
    {
        var username = AddUser(publicKey: null, whitelist: new List<string> { "10.0.0.0/8" });

        using var client = CreatePasswordClient(username);

        Assert.Throws<SshAuthenticationException>(() => client.Connect());
    }

    private string AddUser(RSA? publicKey, List<string>? whitelist = null)
    {
        var username = "u" + Guid.NewGuid().ToString("N")[..12];
        var root = Path.Combine(_server.TempDirectory, "root-" + username);
        Directory.CreateDirectory(root);
        _server.Repository.AddUser(new User
        {
            Username = username,
            HashedPassword = TestCredentials.HashPassword(TestCredentials.Password),
            // The admin UI stores ExportCspBlob(false) as base64.
            RsaPublicKey = publicKey is RSACryptoServiceProvider csp ? Convert.ToBase64String(csp.ExportCspBlob(false)) : null!,
            UserRootDirectory = root,
            OnlyWhitelistedIps = whitelist != null,
            WhitelistedIps = whitelist ?? new List<string>(),
        });
        return username;
    }

    private SftpClient CreateKeyClient(string username, RSA key)
    {
        var pem = new MemoryStream(Encoding.ASCII.GetBytes(key.ExportRSAPrivateKeyPem()));
        var client = new SftpClient(SftpServerFixture.Host, _server.Port, username, new PrivateKeyFile(pem));
        client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(15);
        return client;
    }

    private SftpClient CreatePasswordClient(string username)
    {
        var client = new SftpClient(SftpServerFixture.Host, _server.Port, username, TestCredentials.Password);
        client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(15);
        return client;
    }
}
