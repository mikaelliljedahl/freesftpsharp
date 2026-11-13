using System.Net;
using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;
using Renci.SshNet.Common;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// A server with auto-ban after 3 failed passwords, loopback not exempt (the tests connect from 127.0.0.1), and a
/// fake clock, so a test can let a ban expire.
/// </summary>
public sealed class BanServerFixture : SftpServerFixture
{
    public const int MaxFailures = 3;
    public static readonly TimeSpan BanDuration = TimeSpan.FromMinutes(30);

    public FakeTimeProvider Time { get; } = new(new DateTimeOffset(2026, 11, 13, 8, 0, 0, TimeSpan.Zero));

    protected override TimeProvider CreateTimeProvider() => Time;

    protected override void ConfigureSettings(ServerSettings settings)
    {
        settings.MaxLoginAttemptsBeforeBan = MaxFailures;
        settings.LoginFailureWindowSeconds = 600;
        settings.BanDurationSeconds = (int)BanDuration.TotalSeconds;
        settings.ExemptLoopbackFromBan = false;
    }
}

/// <summary>Global blacklist, global whitelist mode, auto-ban and LastSuccessfulLogin, with SSH.NET over 127.0.0.1.</summary>
public sealed class IpFilterAndBanTests : IClassFixture<BanServerFixture>
{
    private readonly BanServerFixture _server;

    public IpFilterAndBanTests(BanServerFixture server)
    {
        _server = server;

        // The tests in a class run one after the other; start each with a clean state.
        foreach (var ban in _server.BanTracker.GetActiveBans())
            _server.BanTracker.Unban(ban.Address);
        var settings = _server.Repository.ServerSettings;
        settings.BlacklistedIps = new List<string>();
        settings.OnlyWhitelistedIps = false;
        settings.WhitelistedIps = new List<string>();
        _server.Time.Advance(TimeSpan.FromHours(1)); // old failures are out of the window
    }

    [Fact]
    public async Task A_blacklisted_client_is_disconnected_before_the_key_exchange()
    {
        _server.Repository.ServerSettings.BlacklistedIps = new List<string> { "127.0.0.0/8" };

        // The server closes the socket without even sending its identification line.
        Assert.Equal("", await _server.ReadIdentificationAsync());
        using var client = _server.CreateClient();
        Assert.ThrowsAny<Exception>(() => client.Connect());
        Assert.False(client.IsConnected);
    }

    [Fact]
    public async Task The_blacklist_is_read_for_each_connection()
    {
        _server.Repository.ServerSettings.BlacklistedIps = new List<string> { "10.0.0.0/8", "::ffff:192.0.2.0/120" };

        Assert.StartsWith("SSH-2.0-", await _server.ReadIdentificationAsync());
        using var client = _server.Connect();
        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task In_whitelist_mode_an_unlisted_client_is_disconnected()
    {
        var settings = _server.Repository.ServerSettings;
        settings.OnlyWhitelistedIps = true;
        settings.WhitelistedIps = new List<string> { "10.0.0.0/8" };

        Assert.Equal("", await _server.ReadIdentificationAsync());

        settings.WhitelistedIps = new List<string> { "10.0.0.0/8", "127.0.0.1" };

        using var client = _server.Connect();
        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task An_address_is_banned_after_too_many_wrong_passwords_and_the_ban_expires()
    {
        for (var i = 0; i < BanServerFixture.MaxFailures; i++)
        {
            using var wrong = _server.CreateClient(password: "wrong-password");
            Assert.Throws<SshAuthenticationException>(() => wrong.Connect());
        }

        var ban = Assert.Single(_server.BanTracker.GetActiveBans());
        Assert.Equal(IPAddress.Loopback, ban.Address);

        // Banned: even the right password cannot connect, the socket is closed at once.
        Assert.Equal("", await _server.ReadIdentificationAsync());
        using (var banned = _server.CreateClient())
            Assert.ThrowsAny<Exception>(() => banned.Connect());

        _server.Time.Advance(BanServerFixture.BanDuration);

        Assert.Empty(_server.BanTracker.GetActiveBans());
        using var client = _server.Connect();
        Assert.True(client.IsConnected);
    }

    [Fact]
    public void Failures_below_the_limit_do_not_ban()
    {
        for (var i = 0; i < BanServerFixture.MaxFailures - 1; i++)
        {
            using var wrong = _server.CreateClient(password: "wrong-password");
            Assert.Throws<SshAuthenticationException>(() => wrong.Connect());
        }

        Assert.Empty(_server.BanTracker.GetActiveBans());
        using var client = _server.Connect();
        Assert.True(client.IsConnected);
    }

    [Fact]
    public void Unknown_users_count_as_failures()
    {
        for (var i = 0; i < BanServerFixture.MaxFailures; i++)
        {
            using var wrong = _server.CreateClient(username: "no-such-user-" + i);
            Assert.Throws<SshAuthenticationException>(() => wrong.Connect());
        }

        Assert.Single(_server.BanTracker.GetActiveBans());
    }

    [Fact]
    public void An_unbanned_address_can_connect_again()
    {
        for (var i = 0; i < BanServerFixture.MaxFailures; i++)
        {
            using var wrong = _server.CreateClient(password: "wrong-password");
            Assert.Throws<SshAuthenticationException>(() => wrong.Connect());
        }

        Assert.True(_server.BanTracker.Unban(IPAddress.Loopback));

        using var client = _server.Connect();
        Assert.True(client.IsConnected);
    }

    [Fact]
    public void A_successful_login_sets_LastSuccessfulLogin()
    {
        var user = _server.Repository.GetUser(_server.Username);
        user.LastSuccessfulLogin = default;
        _server.Repository.UpdateUser(user);
        var expected = _server.Time.GetUtcNow().UtcDateTime;

        using (var client = _server.Connect())
            Assert.True(client.IsConnected);

        Assert.Equal(expected, _server.Repository.GetUser(_server.Username).LastSuccessfulLogin);
    }

    [Fact]
    public void A_failed_login_does_not_set_LastSuccessfulLogin()
    {
        var user = _server.Repository.GetUser(_server.Username);
        user.LastSuccessfulLogin = default;
        _server.Repository.UpdateUser(user);

        using (var wrong = _server.CreateClient(password: "wrong-password"))
            Assert.Throws<SshAuthenticationException>(() => wrong.Connect());

        Assert.Equal(default, _server.Repository.GetUser(_server.Username).LastSuccessfulLogin);
    }
}
