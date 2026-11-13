using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet.Common;
using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// Login over SSH with users whose passwords are stored in the old SHA-256 format and in the PBKDF2 format (issue #23).
/// </summary>
public sealed class SshNetPasswordMigrationTests : IClassFixture<SftpServerFixture>
{
    private readonly SftpServerFixture _server;

    public SshNetPasswordMigrationTests(SftpServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public void A_user_with_a_legacy_hash_can_log_in_and_then_has_a_pbkdf2_hash()
    {
        _server.AddUser("legacy_user", TestCredentials.LegacySha256Hash("legacy-pw"));

        using (var client = _server.CreateClient(password: "legacy-pw", username: "legacy_user"))
        {
            client.Connect();
            Assert.True(client.IsConnected);
        }

        var stored = _server.Repository.GetUser("legacy_user").HashedPassword;
        Assert.False(PasswordHasher.IsLegacySha256(stored));
        Assert.True(PasswordHasher.Verify("legacy-pw", stored));

        // The second login uses the new hash.
        using (var client = _server.CreateClient(password: "legacy-pw", username: "legacy_user"))
        {
            client.Connect();
            Assert.True(client.IsConnected);
        }

        using var wrong = _server.CreateClient(password: "wrong", username: "legacy_user");
        Assert.Throws<SshAuthenticationException>(() => wrong.Connect());
    }

    [Fact]
    public void A_legacy_hash_rejects_a_wrong_password_and_stays_unchanged()
    {
        var legacy = TestCredentials.LegacySha256Hash("legacy-pw2");
        _server.AddUser("legacy_user2", legacy);

        using var client = _server.CreateClient(password: "wrong", username: "legacy_user2");
        Assert.Throws<SshAuthenticationException>(() => client.Connect());

        Assert.Equal(legacy, _server.Repository.GetUser("legacy_user2").HashedPassword);
    }

    [Fact]
    public void A_user_with_a_pbkdf2_hash_can_log_in()
    {
        var hash = TestCredentials.HashPassword("new-pw");
        _server.AddUser("pbkdf2_user", hash);

        using var client = _server.CreateClient(password: "new-pw", username: "pbkdf2_user");
        client.Connect();

        Assert.True(client.IsConnected);
        Assert.Equal(hash, _server.Repository.GetUser("pbkdf2_user").HashedPassword);
    }

    [Fact]
    public void An_unknown_user_is_rejected()
    {
        using var client = _server.CreateClient(password: "whatever", username: "no_such_user");

        Assert.Throws<SshAuthenticationException>(() => client.Connect());
    }
}
