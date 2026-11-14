using System.Net;
using FreeSftpSharp.Tests.WebClient;
using FreeSftpSharp.Tests.WebUi;
using FxSshSftpServer.Security.Oidc;
using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Permissions;

namespace FreeSftpSharp.Tests.Oidc;

/// <summary>
/// The admin host with both OpenID Connect sign-ins on (#73), against the in-memory <see cref="FakeOidcProvider"/>. The
/// browsers use https://localhost, because the correlation and nonce cookies of the handler are Secure.
/// </summary>
public class OidcHostFactory : WebClientFactory
{
    public const string AdminClientId = "freesftpsharp-admin";
    public const string AdminClientSecret = "admin-secret";
    public const string WebClientId = "freesftpsharp-client";
    public const string TemplateGroup = "partners";

    public FakeOidcProvider Provider { get; } = new FakeOidcProvider().WithClient(AdminClientId, AdminClientSecret).WithClient(WebClientId, null);

    protected virtual bool DisableLocalLogin => false;

    /// <summary>Auth:Oidc:Admin:BootstrapAdmin (#145), or null.</summary>
    protected virtual string? BootstrapAdmin => null;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("Auth:ExternalUsers:RootDirectory", RootDirectory);
        builder.UseSetting("Auth:Oidc:Admin:Authority", FakeOidcProvider.Issuer);
        builder.UseSetting("Auth:Oidc:Admin:ClientId", AdminClientId);
        builder.UseSetting("Auth:Oidc:Admin:ClientSecret", AdminClientSecret);
        builder.UseSetting("Auth:Oidc:Admin:DisplayName", "Test IdP");
        builder.UseSetting("Auth:Oidc:Admin:RequiredRoleValue", "sftp-admin");
        builder.UseSetting("Auth:Oidc:Admin:AutoProvision", "true");
        builder.UseSetting("Auth:Oidc:Admin:RolePermissions:sftp-helpdesk", "ViewConnections, ViewAudit");
        builder.UseSetting("Auth:Oidc:Admin:DisableLocalLogin", DisableLocalLogin ? "true" : "false");
        if (BootstrapAdmin != null)
            builder.UseSetting("Auth:Oidc:Admin:BootstrapAdmin", BootstrapAdmin);
        builder.UseSetting("Auth:Oidc:Client:Authority", FakeOidcProvider.Issuer);
        builder.UseSetting("Auth:Oidc:Client:ClientId", WebClientId);
        builder.UseSetting("Auth:Oidc:Client:DisplayName", "Test IdP");
        builder.UseSetting("Auth:Oidc:Client:RequiredRoleValue", "sftp-user");
        builder.UseSetting("Auth:Oidc:Client:AutoProvision", "true");
        builder.UseSetting("Auth:Oidc:Client:TemplateGroup", TemplateGroup);
        builder.UseSetting("Auth:Oidc:Client:DisableLocalLogin", DisableLocalLogin ? "true" : "false");
        builder.ConfigureTestServices(services =>
        {
            // The handler reaches the provider through its backchannel: here the provider in memory.
            services.Configure<OpenIdConnectOptions>(OidcSignInSetup.AdminScheme, o => o.BackchannelHttpHandler = Provider);
            services.Configure<OpenIdConnectOptions>(OidcSignInSetup.ClientScheme, o => o.BackchannelHttpHandler = Provider);
        });
    }

    /// <summary>A browser on https://localhost with cookies, without following redirects.</summary>
    public OidcBrowser CreateOidcBrowser() =>
        new(CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true }),
            Provider);
}

public sealed class OidcLocalLoginDisabledFactory : OidcHostFactory
{
    protected override bool DisableLocalLogin => true;
}

/// <summary>A new installation without an administrator, with <c>Auth:Oidc:Admin:BootstrapAdmin</c> (#145).</summary>
public sealed class OidcBootstrapFactory : OidcHostFactory
{
    public const string FirstAdmin = "first-admin";

    protected override bool ConfigureAdminCredential => false;

    protected override string? BootstrapAdmin => FirstAdmin;
}

/// <summary>A browser for the code flow: the app, and the provider for the authorize step.</summary>
public sealed class OidcBrowser : IDisposable
{
    private readonly FakeOidcProvider _provider;

    public OidcBrowser(HttpClient http, FakeOidcProvider provider)
    {
        Http = http;
        _provider = provider;
    }

    public HttpClient Http { get; }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>
    /// Starts the sign-in at <paramref name="start"/> (the button of a login page), lets the provider answer with its
    /// form_post page and posts it back to the callback. Returns the answer of the callback.
    /// </summary>
    public async Task<HttpResponseMessage> SignInAsync(string start, Action<Dictionary<string, string>>? tamper = null)
    {
        var challenge = await Http.GetAsync(start, Ct);
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        var authorize = challenge.Headers.Location!;
        Assert.StartsWith(FakeOidcProvider.Issuer + "/authorize?", authorize.AbsoluteUri, StringComparison.Ordinal);

        using var idp = new HttpClient(_provider, disposeHandler: false);
        var page = await idp.GetAsync(authorize, Ct);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var (action, fields) = FakeOidcProvider.ParseFormPost(await page.Content.ReadAsStringAsync(Ct));
        tamper?.Invoke(fields);
        return await Http.PostAsync(action.PathAndQuery, new FormUrlEncodedContent(fields), Ct);
    }

    /// <summary>Follows the redirect to the page after the sign-in, and returns the target of its meta refresh.</summary>
    public async Task<string> FollowDonePageAsync(HttpResponseMessage callback)
    {
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        var done = await Http.GetAsync(callback.Headers.Location!.OriginalString, Ct);
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        var html = await done.Content.ReadAsStringAsync(Ct);
        var match = System.Text.RegularExpressions.Regex.Match(html, "http-equiv=\"refresh\" content=\"0;url=([^\"]+)\"");
        Assert.True(match.Success, html);
        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }

    public void Dispose() => Http.Dispose();
}

/// <summary>The OpenID Connect sign-in of administrators and web client users (#73) through the whole ASP.NET Core pipeline.</summary>
[Collection(AdminUiCollection.Name)]
public sealed class OidcSignInTests : IClassFixture<OidcHostFactory>
{
    private readonly OidcHostFactory _factory;

    public OidcSignInTests(OidcHostFactory factory)
    {
        _factory = factory;
        if (_factory.Repository.GetGroups().All(g => g.Name != OidcHostFactory.TemplateGroup))
        {
            Assert.True(_factory.Repository.AddGroup(new Group
            {
                Name = OidcHostFactory.TemplateGroup,
                Permissions = new() { ["/"] = FilePermissions.List | FilePermissions.Download },
            }));
        }
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static string NewName(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    [Fact]
    public async Task The_login_pages_offer_the_button_next_to_the_password_form()
    {
        using var browser = _factory.CreateOidcBrowser();

        var admin = await (await browser.Http.GetAsync("/Login", Ct)).Content.ReadAsStringAsync(Ct);
        var client = await (await browser.Http.GetAsync("/client/login", Ct)).Content.ReadAsStringAsync(Ct);

        Assert.Contains("id=\"oidc-login\"", admin);
        Assert.Contains("Sign in with Test IdP", admin);
        Assert.Contains("id=\"local-login\"", admin);
        Assert.Contains("id=\"oidc-login\"", client);
        Assert.Contains("id=\"local-login\"", client);
    }

    [Fact]
    public async Task An_existing_administrator_signs_in_without_a_local_password_with_code_flow_PKCE_and_form_post()
    {
        _factory.Provider.SignIn(AdminUiFactory.AdminUserName, roles: ["sftp-admin"]);
        using var browser = _factory.CreateOidcBrowser();

        var callback = await browser.SignInAsync("/Login?handler=Oidc&ReturnUrl=%2Fgeneral");
        var target = await browser.FollowDonePageAsync(callback);

        Assert.Equal("/general", target);
        Assert.Equal(HttpStatusCode.OK, (await browser.Http.GetAsync("/", Ct)).StatusCode);
        var request = _factory.Provider.AuthorizeRequests.Last();
        Assert.Equal("code", request["response_type"]);
        Assert.Equal("form_post", request["response_mode"]);
        Assert.Equal("S256", request["code_challenge_method"]);
        Assert.False(string.IsNullOrEmpty(request["nonce"]));
        Assert.False(string.IsNullOrEmpty(request["state"]));
        Assert.Equal("https://localhost" + OidcSignInSetup.AdminCallbackPath, request["redirect_uri"]);
        Assert.Contains("openid", request["scope"].Split(' '));
        Assert.Contains(_factory.Provider.TokenRequests, t => t.GetValueOrDefault("client_id") == OidcHostFactory.AdminClientId && t.ContainsKey("code_verifier"));
        await _factory.Events.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.LoginOk && e.Username == AdminUiFactory.AdminUserName && e.Method == "oidc" && e.Protocol == "AdminUI");
        await _factory.Events.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.IdpLogin && e.Username == AdminUiFactory.AdminUserName && e.Protocol == "AdminUI");
    }

    [Fact]
    public async Task The_login_cookie_has_no_token_of_the_provider()
    {
        _factory.Provider.SignIn(AdminUiFactory.AdminUserName, roles: ["sftp-admin"]);
        using var browser = _factory.CreateOidcBrowser();
        var callback = await browser.SignInAsync("/Login?handler=Oidc");
        var cookie = Assert.Single(callback.Headers.GetValues("Set-Cookie"), c => c.StartsWith(FxSshSftpServer.Security.AdminAuthenticationSetup.CookieName + "=", StringComparison.Ordinal));

        // Decrypt the ticket of the cookie: only the local claims, no tokens.
        var options = _factory.Services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>>()
            .Get(Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme);
        var ticket = options.TicketDataFormat.Unprotect(Uri.UnescapeDataString(cookie.Split(';')[0].Split('=', 2)[1]));
        Assert.NotNull(ticket);
        Assert.Empty(ticket.Properties.GetTokens());
        Assert.DoesNotContain(ticket.Principal.Claims, c => c.Type is "sub" or "nonce" or "roles" or "id_token");
        Assert.Equal(OidcSignInSetup.AdminScheme, ticket.Principal.FindFirst(OidcClaims.IdentityProviderClaim)?.Value);
    }

    [Fact]
    public async Task An_administrator_without_the_required_role_is_refused_with_a_clear_page()
    {
        _factory.Provider.SignIn(AdminUiFactory.AdminUserName, roles: ["other"]);
        using var browser = _factory.CreateOidcBrowser();

        var callback = await browser.SignInAsync("/Login?handler=Oidc");

        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Equal("/Login?oidc_error=missingrole", callback.Headers.Location!.OriginalString);
        var page = await (await browser.Http.GetAsync(callback.Headers.Location.OriginalString, Ct)).Content.ReadAsStringAsync(Ct);
        Assert.Contains("does not have the role that is needed here", page);
        Assert.Equal(HttpStatusCode.Redirect, (await browser.Http.GetAsync("/", Ct)).StatusCode);
        await _factory.Events.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.LoginFailed && e.Method == "oidc" && e.Protocol == "AdminUI");
    }

    [Fact]
    public async Task A_new_administrator_is_created_with_the_permissions_of_its_role()
    {
        var name = NewName("oidcadmin");
        _factory.Provider.SignIn(name, roles: ["sftp-admin", "sftp-helpdesk"]);
        using var browser = _factory.CreateOidcBrowser();

        await browser.FollowDonePageAsync(await browser.SignInAsync("/Login?handler=Oidc"));

        var admin = await _factory.AdminStore.GetAdminAsync(name, Ct);
        Assert.NotNull(admin);
        Assert.Equal(AdminPermissions.ViewConnections | AdminPermissions.ViewAudit, admin.Permissions);
        Assert.Equal(HttpStatusCode.OK, (await browser.Http.GetAsync("/connections", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.Http.GetAsync("/users", Ct)).StatusCode);
    }

    [Fact]
    public async Task An_admin_sign_in_does_not_open_the_client()
    {
        _factory.Provider.SignIn(AdminUiFactory.AdminUserName, roles: ["sftp-admin", "sftp-user"]);
        using var browser = _factory.CreateOidcBrowser();
        await browser.FollowDonePageAsync(await browser.SignInAsync("/Login?handler=Oidc"));

        var page = await browser.Http.GetAsync("/client", Ct);

        Assert.Equal(HttpStatusCode.Redirect, page.StatusCode);
        Assert.Equal(ClientAuth.LoginPath, page.Headers.Location!.AbsolutePath, ignoreCase: true);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.Http.GetAsync("/client/api/list?path=/", Ct)).StatusCode);
    }

    [Fact]
    public async Task A_user_is_provisioned_in_the_template_group_and_sees_its_files_with_the_group_permissions()
    {
        var name = NewName("oidcuser");
        _factory.Provider.SignIn(name, roles: ["sftp-user"]);
        using var browser = _factory.CreateOidcBrowser();

        var target = await browser.FollowDonePageAsync(await browser.SignInAsync("/client/login?handler=Oidc"));

        Assert.Equal(ClientAuth.BasePath, target);
        var user = _factory.Repository.GetUser(name);
        Assert.NotNull(user);
        Assert.Equal(OidcClaims.ProviderName, user.AuthenticationProvider);
        Assert.Null(user.HashedPassword);
        Assert.Equal(_factory.Repository.GetGroups().Single(g => g.Name == OidcHostFactory.TemplateGroup).Id, user.PrimaryGroupId);
        await File.WriteAllTextAsync(Path.Combine(user.UserRootDirectory, "report.txt"), "hello", Ct);

        var client = new ClientBrowser(browser.Http);
        var (status, html) = await client.OpenFilesAsync();
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Contains("report.txt", await (await browser.Http.GetAsync("/client/api/list?path=/", Ct)).Content.ReadAsStringAsync(Ct));
        Assert.Equal("hello", await (await browser.Http.GetAsync("/client/api/download?path=%2Freport.txt", Ct)).Content.ReadAsStringAsync(Ct));
        // The group gives List and Download only: an upload is refused by the permissions.
        var upload = await client.PostChunkAsync("/new.txt", Guid.NewGuid().ToString("N"), [1, 2, 3], 0, 3);
        Assert.Equal(HttpStatusCode.Forbidden, upload.StatusCode);
        Assert.Contains("id=\"file-browser\"", html);

        await _factory.Events.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.LoginOk && e.Username == name && e.Method == "oidc" && e.Protocol == "HTTP");
        await _factory.Events.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.IdpLogin && e.Username == name && e.Protocol == "HTTP" && e.SessionId != null);
    }

    [Fact]
    public async Task A_client_sign_in_does_not_open_the_admin_UI_and_cannot_set_a_password()
    {
        var name = NewName("oidcsep");
        _factory.Provider.SignIn(name, roles: ["sftp-user", "sftp-admin"]);
        using var browser = _factory.CreateOidcBrowser();
        await browser.FollowDonePageAsync(await browser.SignInAsync("/client/login?handler=Oidc"));

        var admin = await browser.Http.GetAsync("/", Ct);
        Assert.Equal(HttpStatusCode.Redirect, admin.StatusCode);
        Assert.Equal("/Login", admin.Headers.Location!.AbsolutePath);

        var change = await (await browser.Http.GetAsync("/client/changepassword", Ct)).Content.ReadAsStringAsync(Ct);
        Assert.Contains("managed by oidc", change);
    }

    [Fact]
    public async Task A_user_of_the_sign_in_manages_its_keys_and_app_passwords_in_the_web_client()
    {
        var name = NewName("oidcself");
        _factory.Provider.SignIn(name, roles: ["sftp-user"]);
        using var browser = _factory.CreateOidcBrowser();
        await browser.FollowDonePageAsync(await browser.SignInAsync("/client/login?handler=Oidc"));

        var account = await (await browser.Http.GetAsync("/client/account", Ct)).Content.ReadAsStringAsync(Ct);
        Assert.Contains("id=\"keys-local\"", account);
        Assert.Contains("id=\"app-passwords-section\"", account);
        var key = Infrastructure.TestUserKeys.Ed25519();
        var added = await browser.Http.PostAsync("/client/account?handler=AddKeys", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = ClientBrowser.FormToken(account), ["KeysText"] = key.AuthorizedKeysLine,
        }), Ct);
        Assert.Equal(HttpStatusCode.OK, added.StatusCode);
        Assert.Equal(key.Entry.KeyBase64, Assert.Single(_factory.Repository.GetUser(name)!.PublicKeys!).KeyBase64);

        var created = await browser.Http.PostAsync("/client/account?handler=CreateAppPassword", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = ClientBrowser.FormToken(await added.Content.ReadAsStringAsync(Ct)),
            ["AppPasswordName"] = "Finder", ["AppPasswordWebDav"] = "true",
        }), Ct);
        var html = await created.Content.ReadAsStringAsync(Ct);
        var secret = WebUtility.HtmlDecode(System.Text.RegularExpressions.Regex.Match(html, "id=\"new-app-password\">([^<]+)<").Groups[1].Value);
        Assert.False(string.IsNullOrEmpty(secret), html);
        var stored = _factory.Repository.GetUser(name)!;
        Assert.Equal(OidcClaims.ProviderName, stored.AuthenticationProvider);
        Assert.Equal(SshServer.Interfaces.Authentication.UserProtocols.WebDav, Assert.Single(stored.AppPasswords!).Protocols);

        // The app password logs in to WebDAV, not to the web client (which needs the sign-in).
        var logins = _factory.Services.GetRequiredService<FxSsh.SshServerModule.Security.PasswordLoginService>();
        var webdav = await logins.LoginAsync("WebDAV", SshServer.Interfaces.Authentication.UserProtocols.WebDav, name, secret, IPAddress.Loopback, Ct);
        Assert.Equal(FxSsh.SshServerModule.Security.PasswordLoginStatus.Ok, webdav.Status);
        Assert.Equal("app-password", webdav.Method);
        var web = await logins.LoginAsync("HTTP", SshServer.Interfaces.Authentication.UserProtocols.Web, name, secret, IPAddress.Loopback, Ct,
            FxSsh.SshServerModule.Security.PasswordLoginOptions.Interactive);
        Assert.Equal(FxSsh.SshServerModule.Security.PasswordLoginStatus.Failed, web.Status);
    }

    [Fact]
    public async Task A_user_without_the_required_role_is_refused_and_not_created()
    {
        var name = NewName("norole");
        _factory.Provider.SignIn(name, roles: ["guest"]);
        using var browser = _factory.CreateOidcBrowser();

        var callback = await browser.SignInAsync("/client/login?handler=Oidc");

        Assert.Equal("/client/login?oidc_error=missingrole", callback.Headers.Location!.OriginalString);
        var page = await (await browser.Http.GetAsync(callback.Headers.Location.OriginalString, Ct)).Content.ReadAsStringAsync(Ct);
        Assert.Contains("does not have the role that is needed here", page);
        Assert.Null(_factory.Repository.GetUser(name));
    }

    [Fact]
    public async Task A_local_user_of_another_provider_is_not_taken_over()
    {
        var name = NewName("ldapowned");
        _factory.AddUser(name, change: u => u.AuthenticationProvider = "ldap");
        _factory.Provider.SignIn(name, roles: ["sftp-user"]);
        using var browser = _factory.CreateOidcBrowser();

        var callback = await browser.SignInAsync("/client/login?handler=Oidc");

        Assert.Equal("/client/login?oidc_error=accountnotusable", callback.Headers.Location!.OriginalString);
        Assert.Equal("ldap", _factory.Repository.GetUser(name)!.AuthenticationProvider);
    }

    [Fact]
    public async Task A_changed_state_is_refused()
    {
        _factory.Provider.SignIn(AdminUiFactory.AdminUserName, roles: ["sftp-admin"]);
        using var browser = _factory.CreateOidcBrowser();

        var callback = await browser.SignInAsync("/Login?handler=Oidc", fields => fields["state"] = "forged");

        Assert.Equal("/Login?oidc_error=providerfailed", callback.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.Redirect, (await browser.Http.GetAsync("/", Ct)).StatusCode);
    }

    [Fact]
    public async Task A_code_posted_without_the_correlation_cookie_of_the_browser_is_refused()
    {
        _factory.Provider.SignIn(AdminUiFactory.AdminUserName, roles: ["sftp-admin"]);
        using var victim = _factory.CreateOidcBrowser();
        using var attacker = _factory.CreateOidcBrowser();
        var challenge = await attacker.Http.GetAsync("/Login?handler=Oidc", Ct);
        using var idp = new HttpClient(_factory.Provider, disposeHandler: false);
        var (action, fields) = FakeOidcProvider.ParseFormPost(await (await idp.GetAsync(challenge.Headers.Location, Ct)).Content.ReadAsStringAsync(Ct));

        var callback = await victim.Http.PostAsync(action.PathAndQuery, new FormUrlEncodedContent(fields), Ct);

        Assert.Equal("/Login?oidc_error=providerfailed", callback.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task The_client_logout_ends_the_session_at_the_provider()
    {
        var name = NewName("oidcout");
        _factory.Provider.SignIn(name, roles: ["sftp-user"]);
        using var browser = _factory.CreateOidcBrowser();
        await browser.FollowDonePageAsync(await browser.SignInAsync("/client/login?handler=Oidc"));
        var client = new ClientBrowser(browser.Http);
        await client.OpenFilesAsync();
        var token = await client.RequireTokenAsync();

        var logout = await browser.Http.PostAsync("/client/logout", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token }), Ct);
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        Assert.Contains("url=/client/logout-provider", await logout.Content.ReadAsStringAsync(Ct));
        Assert.Equal(HttpStatusCode.Redirect, (await browser.Http.GetAsync("/client", Ct)).StatusCode);

        var provider = await browser.Http.GetAsync("/client/logout-provider", Ct);
        Assert.Equal(HttpStatusCode.Redirect, provider.StatusCode);
        var endSession = provider.Headers.Location!;
        Assert.StartsWith(FakeOidcProvider.Issuer + "/logout?", endSession.AbsoluteUri, StringComparison.Ordinal);
        var query = FakeOidcProvider.Query(endSession);
        Assert.Equal(OidcHostFactory.WebClientId, query["client_id"]);
        Assert.Equal("https://localhost" + OidcSignInSetup.ClientSignedOutCallbackPath, query["post_logout_redirect_uri"]);
        Assert.False(query.ContainsKey("id_token_hint")); // the token was not kept
    }

    [Fact]
    public async Task The_admin_logout_ends_the_session_at_the_provider()
    {
        _factory.Provider.SignIn(AdminUiFactory.AdminUserName, roles: ["sftp-admin"]);
        using var browser = _factory.CreateOidcBrowser();
        await browser.FollowDonePageAsync(await browser.SignInAsync("/Login?handler=Oidc"));
        var page = await (await browser.Http.GetAsync("/Logout", Ct)).Content.ReadAsStringAsync(Ct);

        var logout = await browser.Http.PostAsync("/Logout", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = ClientBrowser.FormToken(page) }), Ct);

        Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
        Assert.StartsWith(FakeOidcProvider.Issuer + "/logout?", logout.Headers.Location!.AbsoluteUri, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Redirect, (await browser.Http.GetAsync("/", Ct)).StatusCode);
    }

    [Fact]
    public async Task A_password_login_is_not_sent_to_the_provider_at_logout()
    {
        using var browser = _factory.CreateOidcBrowser();
        await AdminUiAuthenticationTests.LogInAsync(browser.Http, AdminUiFactory.AdminUserName, AdminUiFactory.AdminPassword);
        var page = await (await browser.Http.GetAsync("/Logout", Ct)).Content.ReadAsStringAsync(Ct);

        var logout = await browser.Http.PostAsync("/Logout", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = ClientBrowser.FormToken(page) }), Ct);

        Assert.Equal("/Login", logout.Headers.Location!.OriginalString);
    }
}

/// <summary>With <c>DisableLocalLogin</c> the password forms are gone and their POST answers 404 (#73).</summary>
[Collection(AdminUiCollection.Name)]
public sealed class OidcLocalLoginDisabledTests : IClassFixture<OidcLocalLoginDisabledFactory>
{
    private readonly OidcLocalLoginDisabledFactory _factory;

    public OidcLocalLoginDisabledTests(OidcLocalLoginDisabledFactory factory)
    {
        _factory = factory;
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("/Login")]
    [InlineData("/client/login")]
    public async Task The_password_form_is_gone_and_its_POST_answers_404(string path)
    {
        using var browser = _factory.CreateOidcBrowser();
        var page = await (await browser.Http.GetAsync(path, Ct)).Content.ReadAsStringAsync(Ct);
        Assert.DoesNotContain("id=\"local-login\"", page);
        Assert.DoesNotContain("type=\"password\"", page);
        Assert.Contains("id=\"oidc-login\"", page);

        // Also without a form token: the request never reaches the page (its antiforgery check would answer 400).
        var post = await browser.Http.PostAsync(path, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["UserName"] = AdminUiFactory.AdminUserName,
            ["Password"] = AdminUiFactory.AdminPassword,
        }), Ct);

        Assert.Equal(HttpStatusCode.NotFound, post.StatusCode);
    }

    [Fact]
    public async Task The_sign_in_still_works()
    {
        _factory.Provider.SignIn(AdminUiFactory.AdminUserName, roles: ["sftp-admin"]);
        using var browser = _factory.CreateOidcBrowser();

        await browser.FollowDonePageAsync(await browser.SignInAsync("/Login?handler=Oidc"));

        Assert.Equal(HttpStatusCode.OK, (await browser.Http.GetAsync("/", Ct)).StatusCode);
    }
}

/// <summary>The first administrator of an installation from the sign-in (#145, <c>Auth:Oidc:Admin:BootstrapAdmin</c>).</summary>
[Collection(AdminUiCollection.Name)]
public sealed class OidcBootstrapAdminTests : IClassFixture<OidcBootstrapFactory>
{
    private readonly OidcBootstrapFactory _factory;

    public OidcBootstrapAdminTests(OidcBootstrapFactory factory)
    {
        _factory = factory;
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Without_an_administrator_only_the_bootstrap_name_becomes_the_first_super_admin()
    {
        using var browser = _factory.CreateOidcBrowser();
        // The admin UI is not closed with 503: its login page offers the sign-in.
        var login = await browser.Http.GetAsync("/Login", Ct);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Contains("id=\"oidc-login\"", await login.Content.ReadAsStringAsync(Ct));

        // Another name with the right role and no mapped permission: refused, nothing created.
        _factory.Provider.SignIn("someone-else", roles: ["sftp-admin"]);
        var other = await browser.SignInAsync("/Login?handler=Oidc");
        Assert.Equal("/Login?oidc_error=missingrole", other.Headers.Location!.OriginalString);
        Assert.False(await _factory.AdminStore.AnyAdminAsync(Ct));

        _factory.Provider.SignIn(OidcBootstrapFactory.FirstAdmin, roles: ["sftp-admin"]);
        await browser.FollowDonePageAsync(await browser.SignInAsync("/Login?handler=Oidc"));

        var admin = await _factory.AdminStore.GetAdminAsync(OidcBootstrapFactory.FirstAdmin, Ct);
        Assert.NotNull(admin);
        Assert.Equal(AdminPermissions.SuperAdmin, admin.Permissions);
        Assert.Equal(OidcClaims.ProviderName, admin.AuthenticationProvider);
        Assert.Equal(HttpStatusCode.OK, (await browser.Http.GetAsync("/admins", Ct)).StatusCode);
    }
}

/// <summary>Without <c>Auth:Oidc</c> nothing changes (#73): no handler, no button, no callback.</summary>
[Collection(AdminUiCollection.Name)]
public sealed class OidcZeroConfigTests : IClassFixture<WebClientFactory>
{
    private readonly WebClientFactory _factory;

    public OidcZeroConfigTests(WebClientFactory factory)
    {
        _factory = factory;
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task No_OpenID_Connect_handler_is_registered()
    {
        var schemes = _factory.Services.GetRequiredService<IAuthenticationSchemeProvider>();

        Assert.Null(await schemes.GetSchemeAsync(OidcSignInSetup.AdminScheme));
        Assert.Null(await schemes.GetSchemeAsync(OidcSignInSetup.ClientScheme));
        Assert.DoesNotContain(await schemes.GetAllSchemesAsync(), s => s.HandlerType == typeof(OpenIdConnectHandler));
    }

    [Theory]
    [InlineData("/Login")]
    [InlineData("/client/login")]
    public async Task The_login_pages_have_no_button_and_the_sign_in_answers_404(string path)
    {
        using var browser = _factory.CreateBrowser();

        var page = await (await browser.GetAsync(path, Ct)).Content.ReadAsStringAsync(Ct);
        Assert.DoesNotContain("oidc-login", page);
        Assert.Contains("id=\"local-login\"", page);
        Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync(path + "?handler=Oidc", Ct)).StatusCode);
    }

    [Fact]
    public async Task The_callback_paths_are_not_handled()
    {
        using var browser = _factory.CreateBrowser();

        var admin = await browser.PostAsync(OidcSignInSetup.AdminCallbackPath, new FormUrlEncodedContent(new Dictionary<string, string> { ["code"] = "x", ["state"] = "y" }), Ct);

        Assert.NotEqual(HttpStatusCode.OK, admin.StatusCode);
        Assert.DoesNotContain("oidc_error", admin.Headers.Location?.OriginalString ?? "", StringComparison.Ordinal);
    }
}
