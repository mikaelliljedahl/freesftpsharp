using Bunit;
using FxSshSftpServer.Components.Pages;
using FxSshSftpServer.Components.Shared;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>The server settings page and the IP access page load the stored settings and save the changes (bUnit).</summary>
public sealed class SettingsPagesTests : AdminUiComponentContext
{
    [Fact]
    public void Server_settings_page_shows_the_stored_settings()
    {
        Repository.ServerSettings.ServerBanner = "MyServer";
        Repository.ServerSettings.IdleTimeout = 300;
        Repository.ServerSettings.BindToAddress = new List<string> { "127.0.0.1", "::1" };

        var page = Render<ServerSettingsPage>();

        Assert.Equal("2222", page.Find("#listen-port").GetAttribute("value"));
        Assert.Equal("MyServer", page.Find("#server-banner").GetAttribute("value"));
        Assert.Equal("300", page.Find("#idle-timeout").GetAttribute("value"));
        Assert.Equal("127.0.0.1\n::1", page.Find("#bind-addresses").GetAttribute("value"));
        Assert.Empty(page.FindAll(".override-note"));
    }

    [Fact]
    public void Server_settings_page_saves_the_changes_and_keeps_the_other_settings()
    {
        Repository.ServerSettings.BlacklistedIps = new List<string> { "203.0.113.0/24" };
        var rsaKey = Repository.ServerSettings.ServerRsaKey;
        var page = Render<ServerSettingsPage>();

        page.Change("#listen-port", "2022");
        page.Change("#bind-addresses", "127.0.0.1\n::1");
        page.Change("#server-banner", "Files");
        page.Change("#idle-timeout", "120");
        page.Change("#enable-direct-tcpip", true);
        page.Submit("#server-settings-form");

        var stored = Repository.ServerSettings;
        Assert.Equal(2022, stored.ListenToPort);
        Assert.Equal(new[] { "127.0.0.1", "::1" }, stored.BindToAddress);
        Assert.Equal("Files", stored.ServerBanner);
        Assert.Equal(120, stored.IdleTimeout);
        Assert.True(stored.EnableDirectTcpIp);
        Assert.Equal(new[] { "203.0.113.0/24" }, stored.BlacklistedIps);
        Assert.Equal(rsaKey, stored.ServerRsaKey);
        Assert.Contains(Toasts.Messages, m => m.Level == ToastLevel.Success);
    }

    [Fact]
    public void Direct_tcpip_shows_a_security_warning()
    {
        var page = Render<ServerSettingsPage>();
        Assert.Empty(page.FindAll("#direct-tcpip-warning"));

        page.Change("#enable-direct-tcpip", true);

        Assert.NotNull(page.Find("#direct-tcpip-warning"));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("70000")]
    public void Server_settings_page_rejects_an_invalid_port(string port)
    {
        var page = Render<ServerSettingsPage>();

        page.Change("#listen-port", port);
        page.Submit("#server-settings-form");

        Assert.Contains("The port must be a number from 1 to 65535.", page.Markup);
        Assert.Equal(2222, Repository.ServerSettings.ListenToPort);
    }

    [Fact]
    public void Server_settings_page_rejects_a_host_name_as_bind_address()
    {
        var page = Render<ServerSettingsPage>();

        page.Change("#bind-addresses", "localhost");
        page.Submit("#server-settings-form");

        Assert.Contains("Not a valid IP address: localhost", page.Markup);
        Assert.NotNull(Repository.ServerSettings.BindToAddress);
        Assert.Empty(Repository.ServerSettings.BindToAddress);
    }

    [Fact]
    public void Server_settings_page_shows_when_the_configuration_overrides_port_and_bind_addresses()
    {
        ListenOptions.Port = "2200";
        ListenOptions.BindToAddress = new List<string> { "10.0.0.5" };

        var page = Render<ServerSettingsPage>();

        var notes = page.FindAll(".override-note");
        Assert.Equal(2, notes.Count);
        Assert.Contains("SshServer:Port", notes[0].TextContent);
        Assert.Contains("2200", notes[0].TextContent);
        Assert.Contains("SshServer:BindToAddress", notes[1].TextContent);
        Assert.Contains("10.0.0.5", notes[1].TextContent);
    }

    [Fact]
    public void Server_settings_page_shows_host_key_fingerprints_but_not_the_private_key()
    {
        var page = Render<ServerSettingsPage>();

        var keys = page.FindAll(".host-key");
        Assert.Equal(2, keys.Count);
        Assert.Contains("SHA256:", keys[1].TextContent); // RSA
        Assert.Contains("rsa-sha2-512", keys[1].TextContent);
        Assert.DoesNotContain((Repository.ServerSettings.ServerRsaKey ?? throw new InvalidOperationException("No RSA host key."))[..40], page.Markup);
        Assert.Contains("curve25519-sha256", page.Markup);
    }

    [Fact]
    public void Access_page_saves_blacklist_whitelist_and_auto_ban_settings()
    {
        var page = Render<AccessControl>();

        page.Change("#blacklist", "203.0.113.0/24\n2001:db8::/32");
        page.Change("#whitelist-mode", true);
        page.Change("#whitelist", "192.168.1.0/24, 10.1.2.3");
        page.Change("#max-attempts", "3");
        page.Change("#failure-window", "60");
        page.Change("#ban-duration", "900");
        page.Change("#exempt-loopback", false);
        page.Submit("#access-form");

        var stored = Repository.ServerSettings;
        Assert.Equal(new[] { "203.0.113.0/24", "2001:db8::/32" }, stored.BlacklistedIps);
        Assert.True(stored.OnlyWhitelistedIps);
        Assert.Equal(new[] { "192.168.1.0/24", "10.1.2.3" }, stored.WhitelistedIps);
        Assert.Equal(3, stored.MaxLoginAttemptsBeforeBan);
        Assert.Equal(60, stored.LoginFailureWindowSeconds);
        Assert.Equal(900, stored.BanDurationSeconds);
        Assert.False(stored.ExemptLoopbackFromBan);
        Assert.Equal(2222, stored.ListenToPort);
    }

    [Theory]
    [InlineData("#blacklist", "10.0.0.0/33")]
    [InlineData("#blacklist", "not-an-ip")]
    [InlineData("#whitelist", "10.0.0")]
    [InlineData("#whitelist", "fe80::1%eth0")]
    public void Access_page_rejects_an_invalid_cidr_entry(string field, string entry)
    {
        var page = Render<AccessControl>();

        page.Change(field, "192.168.0.0/16\n" + entry);
        page.Submit("#access-form");

        Assert.Contains("Not a valid network: " + entry, page.Markup);
        Assert.NotNull(Repository.ServerSettings.BlacklistedIps);
        Assert.Empty(Repository.ServerSettings.BlacklistedIps);
        Assert.NotNull(Repository.ServerSettings.WhitelistedIps);
        Assert.Empty(Repository.ServerSettings.WhitelistedIps);
        Assert.DoesNotContain(Toasts.Messages, m => m.Level == ToastLevel.Success);
    }

    [Fact]
    public void Access_page_notes_that_an_empty_whitelist_checks_nothing()
    {
        var page = Render<AccessControl>();

        page.Change("#whitelist-mode", true);

        Assert.NotNull(page.Find("#empty-whitelist-note"));
    }

    [Fact]
    public void Access_page_lists_the_active_bans_and_unbans_an_address()
    {
        Ban("198.51.100.7");
        Ban("2001:db8::9");
        var page = Render<AccessControl>();

        Assert.Equal("2", page.Find("#ban-count").TextContent);
        Assert.Contains("198.51.100.7", page.Find("#ban-table").TextContent);
        Assert.Contains("2001:db8::9", page.Find("#ban-table").TextContent);

        PageEvents.Trigger(
            () => page.FindAll("#ban-table tbody tr").Single(r => r.TextContent.Contains("198.51.100.7")).QuerySelector(".unban-button")!,
            e => e.Click());

        Assert.False(Bans.IsBanned(System.Net.IPAddress.Parse("198.51.100.7")));
        Assert.True(Bans.IsBanned(System.Net.IPAddress.Parse("2001:db8::9")));
        Assert.Equal("1", page.Find("#ban-count").TextContent);
        Assert.DoesNotContain("198.51.100.7", page.Find("#ban-table").TextContent);
        Assert.Contains(Toasts.Messages, m => m.Text.Contains("198.51.100.7"));
    }

    [Fact]
    public void Access_page_without_bans_says_so()
    {
        var page = Render<AccessControl>();

        Assert.NotNull(page.Find("#no-bans"));
        Assert.Equal("0", page.Find("#ban-count").TextContent);
    }

    [Fact]
    public void Expired_bans_are_not_listed_after_a_refresh()
    {
        Ban("198.51.100.7");
        var page = Render<AccessControl>();

        Clock.Advance(TimeSpan.FromMinutes(31));
        page.Click("#refresh-bans");

        Assert.NotNull(page.Find("#no-bans"));
    }
}
