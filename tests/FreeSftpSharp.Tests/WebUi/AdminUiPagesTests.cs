using System.Net;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>
/// The pages of the admin UI in the in-memory web host: they render (prerendered by the server) after a login with
/// the stored values, and the local static files they need are served.
/// </summary>
[Collection(AdminUiCollection.Name)]
public sealed class AdminUiPagesTests : IClassFixture<AdminUiFactory>
{
    private readonly AdminUiFactory _factory;

    public AdminUiPagesTests(AdminUiFactory factory)
    {
        _factory = factory;
    }

    private async Task<HttpClient> LoggedInBrowserAsync()
    {
        var browser = _factory.CreateBrowser();
        var login = await AdminUiAuthenticationTests.LogInAsync(browser, AdminUiFactory.AdminUserName, AdminUiFactory.AdminPassword);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        return browser;
    }

    private async Task<string> GetPageAsync(HttpClient browser, string path)
    {
        var response = await browser.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData("/", "Dashboard")]
    [InlineData("/users", "Users")]
    [InlineData("/general", "Server settings")]
    [InlineData("/access", "IP access and bans")]
    [InlineData("/connections", "Connections")]
    public async Task Page_renders_after_login_with_the_layout(string path, string heading)
    {
        using var browser = await LoggedInBrowserAsync();

        var html = await GetPageAsync(browser, path);

        Assert.Contains($"<h1 class=\"h3 mb-0\">{heading}</h1>", html);
        Assert.Contains("lib/bootstrap/css/bootstrap.min.css", html);
        Assert.Contains("Log out", html);
        Assert.Contains(AdminUiFactory.AdminUserName, html);
        Assert.DoesNotContain("Radzen", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Access_page_is_behind_the_login()
    {
        using var browser = _factory.CreateBrowser();

        var response = await browser.GetAsync("/access", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/Login", response.Headers.Location!.AbsolutePath);
    }

    [Fact]
    public async Task Pages_show_the_stored_users_settings_and_bans()
    {
        var repository = _factory.Services.GetRequiredService<ISettingsRepository>();
        repository.AddUser(new User { Username = "pages-test-user", UserRootDirectory = "/srv/pages-test", WhitelistedIps = new List<string>() });
        var settings = repository.ServerSettings;
        settings.BlacklistedIps = new List<string> { "203.0.113.0/24" };
        settings.ServerBanner = "PagesTestBanner";
        repository.UpdateServerSettings(settings);
        var tracker = _factory.Services.GetRequiredService<LoginBanTracker>();
        tracker.RecordFailure(IPAddress.Parse("198.51.100.44"), new BanPolicy(1, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5), false));
        using var browser = await LoggedInBrowserAsync();

        Assert.Contains("pages-test-user", await GetPageAsync(browser, "/users"));
        Assert.Contains("PagesTestBanner", await GetPageAsync(browser, "/general"));
        var access = await GetPageAsync(browser, "/access");
        Assert.Contains("203.0.113.0/24", access);
        Assert.Contains("198.51.100.44", access);
    }

    [Theory]
    [InlineData("/lib/bootstrap/css/bootstrap.min.css")]
    [InlineData("/lib/bootstrap-icons/font/bootstrap-icons.min.css")]
    [InlineData("/js/theme.js")]
    [InlineData("/js/site.js")]
    public async Task Local_static_files_are_served_without_a_login(string path)
    {
        using var browser = _factory.CreateBrowser();

        var response = await browser.GetAsync(path, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Blazor_script_is_served()
    {
        using var browser = await LoggedInBrowserAsync();

        var response = await browser.GetAsync("/_framework/blazor.web.js", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public void Radzen_is_not_referenced()
    {
        var references = typeof(Program).Assembly.GetReferencedAssemblies().Select(a => a.Name);

        Assert.DoesNotContain(references, name => name!.StartsWith("Radzen", StringComparison.OrdinalIgnoreCase));
    }
}

[Collection(AdminUiCollection.Name)]
public sealed class ConfiguredListenAdminUiTests : IClassFixture<ConfiguredListenAdminUiFactory>
{
    private readonly ConfiguredListenAdminUiFactory _factory;

    public ConfiguredListenAdminUiTests(ConfiguredListenAdminUiFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Settings_page_and_dashboard_show_the_configured_port_and_bind_address()
    {
        using var browser = _factory.CreateBrowser();
        await AdminUiAuthenticationTests.LogInAsync(browser, AdminUiFactory.AdminUserName, AdminUiFactory.AdminPassword);

        var general = await browser.GetStringAsync("/general", TestContext.Current.CancellationToken);
        Assert.Contains("SshServer:Port", general);
        Assert.Contains("<strong>2200</strong>", general);
        Assert.Contains("SshServer:BindToAddress", general);
        Assert.Contains("<strong>127.0.0.1</strong>", general);

        var home = await browser.GetStringAsync("/", TestContext.Current.CancellationToken);
        Assert.Contains("id=\"dashboard-port\">2200<", home);
        Assert.Contains("from the configuration", home);
    }
}
