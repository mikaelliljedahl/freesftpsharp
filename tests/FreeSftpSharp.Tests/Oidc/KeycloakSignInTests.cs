using System.Net;
using System.Text.RegularExpressions;
using FreeSftpSharp.Tests.WebClient;
using FreeSftpSharp.Tests.WebUi;
using FxSshSftpServer.Security.Oidc;
using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Permissions;

namespace FreeSftpSharp.Tests.Oidc;

/// <summary>
/// The admin host against a real Keycloak (#73) with the realm of <c>tests/keycloak/freesftpsharp-realm.json</c>.
/// FREESFTPSHARP_TEST_KEYCLOAK is the base URL of the Keycloak server (for example http://127.0.0.1:8080); without it
/// the tests are skipped. CI starts <c>quay.io/keycloak/keycloak</c> with the realm imported on the Ubuntu job.
/// </summary>
public sealed class KeycloakHostFactory : WebClientFactory
{
    public const string Variable = "FREESFTPSHARP_TEST_KEYCLOAK";

    public static string? BaseUrl => Environment.GetEnvironmentVariable(Variable)?.TrimEnd('/') is { Length: > 0 } url ? url : null;

    public static string Authority => BaseUrl + "/realms/freesftpsharp";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("Auth:ExternalUsers:RootDirectory", RootDirectory);
        builder.UseSetting("Auth:Oidc:Admin:Authority", Authority);
        builder.UseSetting("Auth:Oidc:Admin:RequireHttpsMetadata", "false");
        builder.UseSetting("Auth:Oidc:Admin:ClientId", "freesftpsharp-admin");
        builder.UseSetting("Auth:Oidc:Admin:ClientSecret", "admin-ci-secret");
        builder.UseSetting("Auth:Oidc:Admin:DisplayName", "Keycloak");
        builder.UseSetting("Auth:Oidc:Admin:RequiredRoleValue", "sftp-admin");
        builder.UseSetting("Auth:Oidc:Admin:AutoProvision", "true");
        builder.UseSetting("Auth:Oidc:Admin:RolePermissions:sftp-admin", "SuperAdmin");
        builder.UseSetting("Auth:Oidc:Client:Authority", Authority);
        builder.UseSetting("Auth:Oidc:Client:RequireHttpsMetadata", "false");
        builder.UseSetting("Auth:Oidc:Client:ClientId", "freesftpsharp-client");
        builder.UseSetting("Auth:Oidc:Client:DisplayName", "Keycloak");
        builder.UseSetting("Auth:Oidc:Client:RequiredRoleValue", "sftp-user");
        builder.UseSetting("Auth:Oidc:Client:AutoProvision", "true");
        builder.UseSetting("Auth:Oidc:Client:TemplateGroup", "partners");
    }

    public HttpClient CreateHttpsBrowser() =>
        CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true });
}

[Collection(AdminUiCollection.Name)]
public sealed partial class KeycloakSignInTests : IClassFixture<KeycloakHostFactory>
{
    private readonly KeycloakHostFactory _factory;

    public KeycloakSignInTests(KeycloakHostFactory factory)
    {
        if (KeycloakHostFactory.BaseUrl == null)
            Assert.Skip($"{KeycloakHostFactory.Variable} is not set (a Keycloak server with the realm tests/keycloak/freesftpsharp-realm.json is needed).");
        _factory = factory;
        if (_factory.Repository.GetGroups().All(g => g.Name != "partners"))
            Assert.True(_factory.Repository.AddGroup(new SshServer.Interfaces.Groups.Group { Name = "partners", Permissions = new() { ["/"] = FilePermissions.List | FilePermissions.Download } }));
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>
    /// The code flow with a browser: the button of the app, the login form of Keycloak, its form_post page back to the
    /// callback of the app. Returns the answer of the callback.
    /// </summary>
    private static async Task<HttpResponseMessage> SignInAsync(HttpClient app, string start, string username, string password)
    {
        var challenge = await app.GetAsync(start, Ct);
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        var authorize = challenge.Headers.Location!;
        Assert.StartsWith(KeycloakHostFactory.Authority, authorize.AbsoluteUri, StringComparison.Ordinal);

        using var keycloak = new HttpClient(new PlainHttpCookieJar(), disposeHandler: true);
        var loginPage = await keycloak.GetStringAsync(authorize, Ct);
        var action = KeycloakFormRegex().Match(loginPage);
        Assert.True(action.Success, loginPage);
        var answer = await keycloak.PostAsync(WebUtility.HtmlDecode(action.Groups[1].Value), new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = username,
            ["password"] = password,
            ["credentialId"] = "",
        }), Ct);
        Assert.Equal(HttpStatusCode.OK, answer.StatusCode);
        var (callback, fields) = FakeOidcProvider.ParseFormPost(await answer.Content.ReadAsStringAsync(Ct));
        Assert.Equal("localhost", callback.Host);
        return await app.PostAsync(callback.PathAndQuery, new FormUrlEncodedContent(fields), Ct);
    }

    private static async Task FollowDonePageAsync(HttpClient app, HttpResponseMessage callback)
    {
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.DoesNotContain(OidcRefusalText.QueryName, callback.Headers.Location!.OriginalString, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, (await app.GetAsync(callback.Headers.Location.OriginalString, Ct)).StatusCode);
    }

    [Fact]
    public async Task An_admin_of_the_realm_signs_in_to_the_admin_UI_without_a_local_password()
    {
        using var app = _factory.CreateHttpsBrowser();

        await FollowDonePageAsync(app, await SignInAsync(app, "/Login?handler=Oidc", "kc-admin", "kc-admin-password"));

        Assert.Equal(HttpStatusCode.OK, (await app.GetAsync("/", Ct)).StatusCode);
        var admin = await _factory.AdminStore.GetAdminAsync("kc-admin", Ct);
        Assert.NotNull(admin);
        Assert.Equal(AdminPermissions.SuperAdmin, admin.Permissions);
    }

    [Fact]
    public async Task A_user_of_the_realm_signs_in_to_the_web_client_and_sees_the_files_of_the_provisioned_account()
    {
        using var app = _factory.CreateHttpsBrowser();

        await FollowDonePageAsync(app, await SignInAsync(app, "/client/login?handler=Oidc", "kc-user", "kc-user-password"));

        var user = _factory.Repository.GetUser("kc-user");
        Assert.NotNull(user);
        Assert.Equal(OidcClaims.ProviderName, user.AuthenticationProvider);
        Assert.Equal(_factory.Repository.GetGroups().Single(g => g.Name == "partners").Id, user.PrimaryGroupId);
        await File.WriteAllTextAsync(Path.Combine(user.UserRootDirectory, "welcome.txt"), "hi", Ct);
        Assert.Contains("welcome.txt", await (await app.GetAsync("/client/api/list?path=/", Ct)).Content.ReadAsStringAsync(Ct));
        var client = new ClientBrowser(app);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostChunkAsync("/up.txt", Guid.NewGuid().ToString("N"), [1], 0, 1)).StatusCode);
    }

    [Fact]
    public async Task A_user_without_the_role_is_refused_with_a_clear_page()
    {
        using var app = _factory.CreateHttpsBrowser();

        var callback = await SignInAsync(app, "/client/login?handler=Oidc", "kc-guest", "kc-guest-password");

        Assert.Equal(ClientAuth.LoginPath + "?oidc_error=missingrole", callback.Headers.Location!.OriginalString);
        Assert.Contains("does not have the role", await (await app.GetAsync(callback.Headers.Location.OriginalString, Ct)).Content.ReadAsStringAsync(Ct));
        Assert.Null(_factory.Repository.GetUser("kc-guest"));
    }

    /// <summary>
    /// The cookies of Keycloak for the test browser. Keycloak marks them Secure also over plain HTTP on 127.0.0.1 (which
    /// a browser accepts as a secure context), and the CookieContainer of .NET would not send them back over HTTP.
    /// Follows the redirects of Keycloak itself.
    /// </summary>
    private sealed class PlainHttpCookieJar : DelegatingHandler
    {
        private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

        public PlainHttpCookieJar()
            : base(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
        {
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            for (var hop = 0; ; hop++)
            {
                if (_cookies.Count > 0)
                    request.Headers.Add("Cookie", string.Join("; ", _cookies.Select(c => c.Key + "=" + c.Value)));
                var response = await base.SendAsync(request, cancellationToken);
                if (response.Headers.TryGetValues("Set-Cookie", out var values))
                {
                    foreach (var pair in values.Select(v => v.Split(';')[0].Split('=', 2)).Where(p => p.Length == 2))
                        _cookies[pair[0].Trim()] = pair[1];
                }
                if (response.StatusCode is not (HttpStatusCode.Redirect or HttpStatusCode.Found or HttpStatusCode.SeeOther) || hop >= 10
                    || response.Headers.Location is not { } location)
                {
                    return response;
                }
                request = new HttpRequestMessage(HttpMethod.Get, new Uri(request.RequestUri!, location));
            }
        }
    }

    [GeneratedRegex("<form[^>]*id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"", RegexOptions.IgnoreCase)]
    private static partial Regex KeycloakFormRegex();
}
