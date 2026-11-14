using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet;
using Renci.SshNet.Common;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Users;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// Public key authentication with several keys per user (ed25519, ECDSA, RSA; the whole key blob is compared, issue #58),
/// the allowed login methods of a user and the per-user IP whitelist, with SSH.NET.
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
        var key = TestUserKeys.Rsa();
        var username = AddUser(keys: [key.Entry]);

        using var client = CreateKeyClient(username, key);
        client.Connect();

        Assert.True(client.IsConnected);
        Assert.Equal("/", client.WorkingDirectory);
    }

    [Fact]
    public void A_user_with_an_ed25519_and_an_rsa_key_logs_in_with_either_and_a_third_key_is_refused()
    {
        var ed25519 = TestUserKeys.Ed25519();
        var rsa = TestUserKeys.Rsa();
        var username = AddUser(keys: [ed25519.Entry, rsa.Entry]);

        using (var client = CreateKeyClient(username, ed25519))
        {
            client.Connect();
            Assert.True(client.IsConnected);
        }
        using (var client = CreateKeyClient(username, rsa))
        {
            client.Connect();
            Assert.True(client.IsConnected);
        }
        using (var client = CreateKeyClient(username, TestUserKeys.Ed25519()))
        {
            Assert.Throws<SshAuthenticationException>(() => client.Connect());
        }
    }

    [Fact]
    public void An_ecdsa_key_is_accepted()
    {
        var key = TestUserKeys.EcdsaNistP256();
        var username = AddUser(keys: [key.Entry]);

        using var client = CreateKeyClient(username, key);
        client.Connect();

        Assert.True(client.IsConnected);
    }

    [Fact]
    public void A_key_whose_stored_fingerprint_matches_but_whose_blob_differs_is_refused()
    {
        var client = TestUserKeys.Ed25519();
        var stored = TestUserKeys.Ed25519().Entry;
        stored.Fingerprint = client.Entry.Fingerprint;
        var username = AddUser(keys: [stored]);

        using var sftp = CreateKeyClient(username, client);

        Assert.Throws<SshAuthenticationException>(() => sftp.Connect());
    }

    [Fact]
    public void Another_public_key_is_rejected()
    {
        var username = AddUser(keys: [TestUserKeys.Rsa().Entry]);

        using var client = CreateKeyClient(username, TestUserKeys.Rsa());

        Assert.Throws<SshAuthenticationException>(() => client.Connect());
    }

    [Fact]
    public void Public_key_is_rejected_for_a_user_without_a_key()
    {
        var username = AddUser(keys: null);

        using var client = CreateKeyClient(username, TestUserKeys.Ed25519());

        Assert.Throws<SshAuthenticationException>(() => client.Connect());
    }

    [Fact]
    public void An_expired_key_is_refused_and_the_other_key_still_works()
    {
        var expired = TestUserKeys.Ed25519();
        expired.Entry.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
        var valid = TestUserKeys.Ed25519();
        var username = AddUser(keys: [expired.Entry, valid.Entry]);

        using (var client = CreateKeyClient(username, expired))
            Assert.Throws<SshAuthenticationException>(() => client.Connect());
        using (var client = CreateKeyClient(username, valid))
        {
            client.Connect();
            Assert.True(client.IsConnected);
        }
    }

    [Fact]
    public void A_removed_key_is_refused_at_the_next_connection()
    {
        var key = TestUserKeys.Ed25519();
        var username = AddUser(keys: [key.Entry]);
        using (var client = CreateKeyClient(username, key))
            client.Connect();

        Assert.True(new UserAdministrationService(_server.Repository).RemovePublicKey(username, key.Entry.KeyBase64));

        using var again = CreateKeyClient(username, key);
        Assert.Throws<SshAuthenticationException>(() => again.Connect());
    }

    [Fact]
    public void A_user_that_may_use_only_keys_is_refused_with_the_right_password()
    {
        var key = TestUserKeys.Ed25519();
        var username = AddUser(keys: [key.Entry], allowed: AuthMethods.PublicKey);

        using (var client = CreatePasswordClient(username))
            Assert.Throws<SshAuthenticationException>(() => client.Connect());
        using (var client = CreateKeyClient(username, key))
        {
            client.Connect();
            Assert.True(client.IsConnected);
        }
    }

    [Fact]
    public void A_user_that_may_use_only_the_password_is_refused_with_its_key()
    {
        var key = TestUserKeys.Ed25519();
        var username = AddUser(keys: [key.Entry], allowed: AuthMethods.Password);

        using (var client = CreateKeyClient(username, key))
            Assert.Throws<SshAuthenticationException>(() => client.Connect());
        using (var client = CreatePasswordClient(username))
        {
            client.Connect();
            Assert.True(client.IsConnected);
        }
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
        var username = AddUser(keys: null, whitelist: new List<string> { "127.0.0.0/8" });

        using var client = CreatePasswordClient(username);
        client.Connect();

        Assert.True(client.IsConnected);
    }

    [Fact]
    public void Client_outside_the_ip_whitelist_is_rejected_even_with_the_right_password()
    {
        var username = AddUser(keys: null, whitelist: new List<string> { "10.0.0.0/8" });

        using var client = CreatePasswordClient(username);

        Assert.Throws<SshAuthenticationException>(() => client.Connect());
    }

    private string AddUser(List<PublicKeyEntry>? keys, List<string>? whitelist = null, AuthMethods allowed = AuthMethods.All)
    {
        var username = "u" + Guid.NewGuid().ToString("N")[..12];
        var root = Path.Combine(_server.TempDirectory, "root-" + username);
        Directory.CreateDirectory(root);
        _server.Repository.AddUser(new User
        {
            Username = username,
            HashedPassword = TestCredentials.HashPassword(TestCredentials.Password),
            PublicKeys = keys,
            AllowedAuthMethods = allowed,
            UserRootDirectory = root,
            OnlyWhitelistedIps = whitelist != null,
            WhitelistedIps = whitelist ?? new List<string>(),
        });
        return username;
    }

    private SftpClient CreateKeyClient(string username, TestUserKey key)
    {
        var client = new SftpClient(SftpServerFixture.Host, _server.Port, username, key.ToPrivateKeyFile());
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
