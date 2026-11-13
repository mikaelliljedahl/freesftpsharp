using System.Net;
using System.Text.RegularExpressions;

namespace FreeSftpSharp.Tests.WebUi;

[Collection(AdminUiCollection.Name)]
public sealed partial class AdminUiAuthenticationTests : IClassFixture<AdminUiFactory>
{
    private readonly AdminUiFactory _factory;

    public AdminUiAuthenticationTests(AdminUiFactory factory)
    {
        _factory = factory;
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/users")]
    [InlineData("/general")]
    [InlineData("/Users")]
    [InlineData("/some/unknown/page")]
    public async Task Anonymous_page_request_redirects_to_the_login_page(string path)
    {
        using var browser = _factory.CreateBrowser();

        var response = await browser.GetAsync(path, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/Login", response.Headers.Location!.AbsolutePath);
    }

    [Fact]
    public async Task Anonymous_blazor_hub_negotiate_is_rejected_with_401()
    {
        using var browser = _factory.CreateBrowser();

        var response = await browser.PostAsync("/_blazor/negotiate?negotiateVersion=1", null, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Anonymous_blazor_hub_connect_is_rejected_with_401()
    {
        using var browser = _factory.CreateBrowser();

        var response = await browser.GetAsync("/_blazor?id=abc", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Login_page_is_reachable_anonymously_and_has_an_antiforgery_token()
    {
        using var browser = _factory.CreateBrowser();

        var response = await browser.GetAsync("/Login", TestContext.Current.CancellationToken);
        var html = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Matches(AntiforgeryTokenRegex(), html);
    }

    [Fact]
    public async Task Static_files_needed_by_the_login_page_are_served_anonymously()
    {
        using var browser = _factory.CreateBrowser();

        var response = await browser.GetAsync("/css/site.css", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Login_with_correct_credentials_gives_access_to_the_pages_and_the_hub()
    {
        using var browser = _factory.CreateBrowser();

        var login = await LogInAsync(browser, AdminUiFactory.AdminUserName, AdminUiFactory.AdminPassword);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.Equal("/", login.Headers.Location!.OriginalString);

        var home = await browser.GetAsync("/", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, home.StatusCode);
        Assert.Contains("blazor.web.js", await home.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        var negotiate = await browser.PostAsync("/_blazor/negotiate?negotiateVersion=1", null, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, negotiate.StatusCode);
    }

    [Fact]
    public async Task Login_follows_a_local_return_url()
    {
        using var browser = _factory.CreateBrowser();

        var login = await LogInAsync(browser, AdminUiFactory.AdminUserName, AdminUiFactory.AdminPassword, returnUrl: "/general");

        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.Equal("/general", login.Headers.Location!.OriginalString);
    }

    [Theory]
    [InlineData("https://evil.example/")]
    [InlineData("//evil.example/")]
    [InlineData("/\\evil.example/")]
    public async Task Login_does_not_redirect_to_another_site(string returnUrl)
    {
        using var browser = _factory.CreateBrowser();

        var login = await LogInAsync(browser, AdminUiFactory.AdminUserName, AdminUiFactory.AdminPassword, returnUrl);

        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.Equal("/", login.Headers.Location!.OriginalString);
    }

    [Theory]
    [InlineData(AdminUiFactory.AdminUserName, "wrong password")]
    [InlineData("root", AdminUiFactory.AdminPassword)]
    [InlineData("", "")]
    public async Task Login_with_wrong_credentials_gives_no_access(string userName, string password)
    {
        using var browser = _factory.CreateBrowser();

        var login = await LogInAsync(browser, userName, password);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Contains("Invalid user name or password", await login.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        var home = await browser.GetAsync("/", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, home.StatusCode);
    }

    [Fact]
    public async Task Login_post_without_antiforgery_token_is_rejected()
    {
        using var browser = _factory.CreateBrowser();

        var response = await browser.PostAsync("/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["UserName"] = AdminUiFactory.AdminUserName,
            ["Password"] = AdminUiFactory.AdminPassword,
        }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var home = await browser.GetAsync("/", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, home.StatusCode);
    }

    [Fact]
    public async Task Logout_ends_the_session()
    {
        using var browser = _factory.CreateBrowser();
        await LogInAsync(browser, AdminUiFactory.AdminUserName, AdminUiFactory.AdminPassword);

        var logoutPage = await browser.GetAsync("/Logout", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, logoutPage.StatusCode);
        var token = ExtractToken(await logoutPage.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        var logout = await browser.PostAsync("/Logout", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
        }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);

        var home = await browser.GetAsync("/", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, home.StatusCode);
        Assert.Equal("/Login", home.Headers.Location!.AbsolutePath);
    }

    [Fact]
    public async Task Auth_cookie_is_http_only()
    {
        using var browser = _factory.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = false });
        var loginPage = await browser.GetAsync("/Login", TestContext.Current.CancellationToken);
        var token = ExtractToken(await loginPage.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var antiforgeryCookie = loginPage.Headers.GetValues("Set-Cookie").First().Split(';')[0];

        using var request = new HttpRequestMessage(HttpMethod.Post, "/Login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["UserName"] = AdminUiFactory.AdminUserName,
                ["Password"] = AdminUiFactory.AdminPassword,
                ["__RequestVerificationToken"] = token,
            }),
        };
        request.Headers.Add("Cookie", antiforgeryCookie);
        var login = await browser.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        var authCookie = login.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith(".FxSshSftpServer.Admin=", StringComparison.Ordinal));
        Assert.Contains("httponly", authCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", authCookie, StringComparison.OrdinalIgnoreCase);
    }

    internal static async Task<HttpResponseMessage> LogInAsync(HttpClient browser, string userName, string password, string? returnUrl = null)
    {
        var loginUrl = returnUrl is null ? "/Login" : "/Login?ReturnUrl=" + Uri.EscapeDataString(returnUrl);
        var page = await browser.GetAsync(loginUrl, TestContext.Current.CancellationToken);
        var token = ExtractToken(await page.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        return await browser.PostAsync(loginUrl, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["UserName"] = userName,
            ["Password"] = password,
            ["__RequestVerificationToken"] = token,
        }), TestContext.Current.CancellationToken);
    }

    private static string ExtractToken(string html) =>
        WebUtility.HtmlDecode(AntiforgeryTokenRegex().Match(html).Groups[1].Value);

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryTokenRegex();
}

[Collection(AdminUiCollection.Name)]
public sealed class UnconfiguredAdminUiTests : IClassFixture<UnconfiguredAdminUiFactory>
{
    private readonly UnconfiguredAdminUiFactory _factory;

    public UnconfiguredAdminUiTests(UnconfiguredAdminUiFactory factory)
    {
        _factory = factory;
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/users")]
    [InlineData("/general")]
    [InlineData("/Login")]
    [InlineData("/css/site.css")]
    public async Task Without_an_admin_credential_the_ui_answers_503(string path)
    {
        using var browser = _factory.CreateBrowser();

        var response = await browser.GetAsync(path, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("--hash-admin-password", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Without_an_admin_credential_the_hub_is_closed()
    {
        using var browser = _factory.CreateBrowser();

        var response = await browser.PostAsync("/_blazor/negotiate?negotiateVersion=1", null, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }
}

[CollectionDefinition(Name)]
public sealed class AdminUiCollection
{
    public const string Name = "Admin UI";
}
