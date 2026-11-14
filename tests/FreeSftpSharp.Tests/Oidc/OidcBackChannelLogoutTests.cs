using System.Net;
using FreeSftpSharp.Tests.WebClient;
using FreeSftpSharp.Tests.WebUi;
using FxSshSftpServer.Security.Oidc;
using FxSshSftpServer.WebClient;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces.Connections;

namespace FreeSftpSharp.Tests.Oidc;

/// <summary>
/// OpenID Connect Back-Channel Logout 1.0 (#145) against the in-memory provider: a valid logout_token ends the matching
/// web client sessions and admin login cookies; an invalid one is refused with 400 and ends nothing.
/// </summary>
[Collection(AdminUiCollection.Name)]
public sealed class OidcBackChannelLogoutTests : IClassFixture<OidcHostFactory>
{
    private readonly OidcHostFactory _factory;

    public OidcBackChannelLogoutTests(OidcHostFactory factory)
    {
        _factory = factory;
        if (_factory.Repository.GetGroups().All(g => g.Name != OidcHostFactory.TemplateGroup))
            Assert.True(_factory.Repository.AddGroup(new SshServer.Interfaces.Groups.Group { Name = OidcHostFactory.TemplateGroup }));
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static string NewName(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    private async Task<HttpResponseMessage> PostLogoutAsync(string path, string? token)
    {
        using var provider = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = false,
        });
        var form = new Dictionary<string, string>();
        if (token != null)
            form["logout_token"] = token;
        return await provider.PostAsync(path, new FormUrlEncodedContent(form), Ct);
    }

    private async Task<OidcBrowser> SignInClientAsync(string name, string? sid)
    {
        _factory.Provider.SignIn(name, roles: ["sftp-user"], sid: sid);
        var browser = _factory.CreateOidcBrowser();
        await browser.FollowDonePageAsync(await browser.SignInAsync("/client/login?handler=Oidc"));
        Assert.Equal(HttpStatusCode.OK, (await browser.Http.GetAsync("/client", Ct)).StatusCode);
        return browser;
    }

    private async Task<OidcBrowser> SignInAdminAsync(string sid)
    {
        _factory.Provider.SignIn(AdminUiFactory.AdminUserName, roles: ["sftp-admin"], sid: sid);
        var browser = _factory.CreateOidcBrowser();
        await browser.FollowDonePageAsync(await browser.SignInAsync("/Login?handler=Oidc"));
        Assert.Equal(HttpStatusCode.OK, (await browser.Http.GetAsync("/", Ct)).StatusCode);
        return browser;
    }

    private int HttpSessionsOf(string name) =>
        _factory.Services.GetRequiredService<IConnectionRegistry>().GetAll().Count(c => c.Username == name && c.Protocol == ClientAuth.Protocol);

    [Fact]
    public async Task A_logout_with_the_sid_ends_that_web_client_session_only()
    {
        var name = NewName("bcl");
        using var ended = await SignInClientAsync(name, "sid-" + name + "-1");
        using var other = await SignInClientAsync(name, "sid-" + name + "-2");
        Assert.Equal(2, HttpSessionsOf(name));

        var response = await PostLogoutAsync(OidcSignInSetup.ClientBackChannelLogoutPath,
            _factory.Provider.LogoutToken(OidcHostFactory.WebClientId, "sid-" + name + "-1", "sub-" + name));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal(HttpStatusCode.Redirect, (await ended.Http.GetAsync("/client", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await other.Http.GetAsync("/client", Ct)).StatusCode);
        Assert.Equal(1, HttpSessionsOf(name));
    }

    [Fact]
    public async Task A_logout_with_the_sub_only_ends_every_web_client_session_of_the_account()
    {
        var name = NewName("bcs");
        using var first = await SignInClientAsync(name, sid: null);
        using var second = await SignInClientAsync(name, "sid-" + name);

        var response = await PostLogoutAsync(OidcSignInSetup.ClientBackChannelLogoutPath, _factory.Provider.LogoutToken(OidcHostFactory.WebClientId, null, "sub-" + name));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await first.Http.GetAsync("/client", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await second.Http.GetAsync("/client", Ct)).StatusCode);
        Assert.Equal(0, HttpSessionsOf(name));
    }

    [Fact]
    public async Task A_logout_ends_the_admin_login_cookie_and_a_new_sign_in_works()
    {
        var sid = "sid-admin-" + Guid.NewGuid().ToString("N")[..8];
        using var browser = await SignInAdminAsync(sid);

        var response = await PostLogoutAsync(OidcSignInSetup.AdminBackChannelLogoutPath, _factory.Provider.LogoutToken(OidcHostFactory.AdminClientId, sid, null));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var after = await browser.Http.GetAsync("/", Ct);
        Assert.Equal(HttpStatusCode.Redirect, after.StatusCode);
        Assert.Equal("/Login", after.Headers.Location!.AbsolutePath);

        // A new sign-in (after the logout) is a new session, also with the same sid.
        using var again = await SignInAdminAsync(sid);
    }

    [Fact]
    public async Task A_password_login_of_the_admin_is_not_ended_by_a_logout_of_the_provider()
    {
        using var browser = _factory.CreateOidcBrowser();
        await AdminUiAuthenticationTests.LogInAsync(browser.Http, AdminUiFactory.AdminUserName, AdminUiFactory.AdminPassword);

        await PostLogoutAsync(OidcSignInSetup.AdminBackChannelLogoutPath, _factory.Provider.LogoutToken(OidcHostFactory.AdminClientId, null, "sub-" + AdminUiFactory.AdminUserName));

        Assert.Equal(HttpStatusCode.OK, (await browser.Http.GetAsync("/", Ct)).StatusCode);
    }

    public static TheoryData<string> InvalidTokens() =>
    [
        "missing", "garbage", "other-key", "wrong-audience", "wrong-issuer", "nonce", "no-events", "no-sid-or-sub", "unsigned", "id-token-type", "expired",
    ];

    [Theory]
    [MemberData(nameof(InvalidTokens))]
    public async Task An_invalid_logout_token_is_refused_and_ends_nothing(string kind)
    {
        var name = NewName("bci");
        var sid = "sid-" + name;
        using var browser = await SignInClientAsync(name, sid);
        var provider = _factory.Provider;
        var audience = OidcHostFactory.WebClientId;
        var token = kind switch
        {
            "missing" => null,
            "garbage" => "not.a.jwt",
            "other-key" => provider.LogoutToken(audience, sid, null, otherKey: true),
            "wrong-audience" => provider.LogoutToken(OidcHostFactory.AdminClientId, sid, null),
            "wrong-issuer" => provider.LogoutToken(audience, sid, null, issuer: "https://evil.test"),
            "nonce" => provider.LogoutToken(audience, sid, null, c => c["nonce"] = "n-1"),
            "no-events" => provider.LogoutToken(audience, sid, null, c => c.Remove("events")),
            "no-sid-or-sub" => provider.LogoutToken(audience, null, null),
            "unsigned" => FakeOidcProvider.UnsignedLogoutToken(audience, sid),
            "id-token-type" => provider.LogoutToken(audience, sid, null, type: "at+jwt"),
            "expired" => provider.LogoutToken(audience, sid, null, age: TimeSpan.FromHours(1)),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };

        var response = await PostLogoutAsync(OidcSignInSetup.ClientBackChannelLogoutPath, token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("invalid_request", await response.Content.ReadAsStringAsync(Ct));
        Assert.Equal(HttpStatusCode.OK, (await browser.Http.GetAsync("/client", Ct)).StatusCode);
    }
}
