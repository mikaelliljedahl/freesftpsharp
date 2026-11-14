using System.Net;
using System.Text.RegularExpressions;
using FxSshSftpServer.Security;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>
/// The admin UI with several stored administrators (#60). The configured AdminAuth account is not imported, because
/// the store has administrators already.
/// </summary>
public sealed class StoredAdminsUiFactory : AdminUiFactory
{
    public const string Password = "Stored-Password-7";
    public static readonly string Hash = PasswordHasher.Hash(Password, PasswordHasher.MinimumIterations);

    public StoredAdminsUiFactory()
    {
        var role = new Role { Name = "tenant-a" };
        AdminStore.AddRoleAsync(role, CancellationToken.None).GetAwaiter().GetResult();
        Add("root", AdminPermissions.SuperAdmin);
        Add("users-only", AdminPermissions.ManageUsers);
        Add("settings-only", AdminPermissions.ManageSettings);
        Add("viewer", AdminPermissions.ViewConnections | AdminPermissions.ViewAudit);
        Add("admins-only", AdminPermissions.ManageAdmins);
        Add("tenant", AdminPermissions.ManageUsers | AdminPermissions.ManageSettings, admin => admin.ScopeRoleId = role.Id);
        Add("disabled", AdminPermissions.SuperAdmin, admin => admin.Status = AdminStatus.Disabled);
        Add("lan-only", AdminPermissions.SuperAdmin, admin => admin.AllowedIps = ["10.0.0.0/8"]);
        Add("must-change", AdminPermissions.ManageUsers, admin => admin.MustChangePassword = true);
        Add("demoted", AdminPermissions.ManageUsers);
        Add("removed", AdminPermissions.ManageUsers);
    }

    public void Add(string name, AdminPermissions permissions, Action<Admin>? configure = null)
    {
        var admin = new Admin { Username = name, PasswordHash = Hash, Permissions = permissions };
        configure?.Invoke(admin);
        Assert.True(AdminStore.AddAdminAsync(admin, CancellationToken.None).GetAwaiter().GetResult());
    }
}

[Collection(AdminUiCollection.Name)]
public sealed partial class AdminAuthorizationTests : IClassFixture<StoredAdminsUiFactory>
{
    private readonly StoredAdminsUiFactory _factory;

    public AdminAuthorizationTests(StoredAdminsUiFactory factory)
    {
        _factory = factory;
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private async Task<HttpClient> LogInAsync(string name)
    {
        var browser = _factory.CreateBrowser();
        var login = await AdminUiAuthenticationTests.LogInAsync(browser, name, StoredAdminsUiFactory.Password);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        return browser;
    }

    public static TheoryData<string, string, HttpStatusCode> Matrix()
    {
        var pages = new (string Path, AdminPermissions Permission)[]
        {
            ("/users", AdminPermissions.ManageUsers),
            ("/connections", AdminPermissions.ViewConnections),
            ("/general", AdminPermissions.ManageSettings),
            ("/access", AdminPermissions.ManageSettings),
            ("/audit", AdminPermissions.ViewAudit),
            ("/admins", AdminPermissions.ManageAdmins),
            ("/roles", AdminPermissions.ManageAdmins),
        };
        var admins = new (string Name, AdminPermissions Effective)[]
        {
            ("root", AdminPermissionRules.Everything),
            ("users-only", AdminPermissions.ManageUsers),
            ("settings-only", AdminPermissions.ManageSettings),
            ("viewer", AdminPermissions.ViewConnections | AdminPermissions.ViewAudit),
            ("admins-only", AdminPermissions.ManageAdmins),
            // The scope masks the settings permission away: a scoped administrator manages only its users.
            ("tenant", AdminPermissions.ManageUsers),
        };

        var data = new TheoryData<string, string, HttpStatusCode>();
        foreach (var (name, effective) in admins)
        {
            data.Add(name, "/", HttpStatusCode.OK);
            foreach (var (path, permission) in pages)
                data.Add(name, path, effective.HasFlag(permission) ? HttpStatusCode.OK : HttpStatusCode.Forbidden);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public async Task Each_page_needs_the_policy_of_its_permission(string admin, string path, HttpStatusCode expected)
    {
        using var browser = await LogInAsync(admin);

        var response = await browser.GetAsync(path, Ct);

        Assert.Equal(expected, response.StatusCode);
    }

    [Fact]
    public async Task An_admin_with_manage_users_only_gets_403_for_the_settings_page_and_its_hub_still_works()
    {
        using var browser = await LogInAsync("users-only");

        var settings = await browser.GetAsync("/general", Ct);
        Assert.Equal(HttpStatusCode.Forbidden, settings.StatusCode);
        Assert.Contains("Access denied", await settings.Content.ReadAsStringAsync(Ct));

        var negotiate = await browser.PostAsync("/_blazor/negotiate?negotiateVersion=1", null, Ct);
        Assert.Equal(HttpStatusCode.OK, negotiate.StatusCode);
    }

    [Fact]
    public async Task The_menu_shows_only_the_pages_of_the_permissions()
    {
        using var browser = await LogInAsync("users-only");

        // The users page has no links of its own to the other pages.
        var html = await (await browser.GetAsync("/users", Ct)).Content.ReadAsStringAsync(Ct);

        Assert.Contains("href=\"users\"", html);
        Assert.DoesNotContain("href=\"general\"", html);
        Assert.DoesNotContain("href=\"admins\"", html);
        Assert.DoesNotContain("href=\"audit\"", html);
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("lan-only")] // the test server has no client address, which is not in 10.0.0.0/8
    public async Task A_disabled_administrator_or_one_from_a_wrong_network_cannot_log_in(string name)
    {
        using var browser = _factory.CreateBrowser();

        var login = await AdminUiAuthenticationTests.LogInAsync(browser, name, StoredAdminsUiFactory.Password);

        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Contains("Invalid user name or password", await login.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task The_configured_account_is_not_imported_when_administrators_are_stored()
    {
        using var browser = _factory.CreateBrowser();

        var login = await AdminUiAuthenticationTests.LogInAsync(browser, AdminUiFactory.AdminUserName, AdminUiFactory.AdminPassword);

        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Null(await _factory.AdminStore.GetAdminAsync(AdminUiFactory.AdminUserName, Ct));
    }

    [Fact]
    public async Task A_change_of_the_permissions_ends_the_existing_sessions()
    {
        using var browser = await LogInAsync("demoted");
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/users", Ct)).StatusCode);

        var stored = (await _factory.AdminStore.GetAdminAsync("demoted", Ct))!;
        stored.Permissions = AdminPermissions.ViewAudit;
        await _factory.AdminStore.UpdateAdminAsync(stored, Ct);

        var response = await browser.GetAsync("/users", Ct);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/Login", response.Headers.Location!.AbsolutePath);
        // The old cookie is gone: also a page that needs no permission asks for a login.
        Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync("/", Ct)).StatusCode);
    }

    [Fact]
    public async Task A_removed_administrator_loses_its_session_and_its_hub()
    {
        using var browser = await LogInAsync("removed");
        var stored = (await _factory.AdminStore.GetAdminAsync("removed", Ct))!;
        await _factory.AdminStore.RemoveAdminAsync(stored.Id, Ct);

        var negotiate = await browser.PostAsync("/_blazor/negotiate?negotiateVersion=1", null, Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, negotiate.StatusCode);
    }

    [Fact]
    public async Task An_administrator_that_must_change_its_password_can_do_nothing_else_first()
    {
        using var browser = _factory.CreateBrowser();
        var login = await AdminUiAuthenticationTests.LogInAsync(browser, "must-change", StoredAdminsUiFactory.Password, returnUrl: "/users");
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.Equal("/ChangePassword?ReturnUrl=%2Fusers", login.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.GetAsync("/users", Ct)).StatusCode);

        var page = await browser.GetAsync("/ChangePassword", Ct);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var token = ExtractToken(await page.Content.ReadAsStringAsync(Ct));

        var wrong = await PostChangePasswordAsync(browser, token, "wrong-current", "Brand-New-Password-1");
        Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
        Assert.Contains("The current password is not correct.", await wrong.Content.ReadAsStringAsync(Ct));

        var changed = await PostChangePasswordAsync(browser, token, StoredAdminsUiFactory.Password, "Brand-New-Password-1", returnUrl: "/users");
        Assert.Equal(HttpStatusCode.Redirect, changed.StatusCode);
        Assert.Equal("/users", changed.Headers.Location!.OriginalString);

        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/users", Ct)).StatusCode);
        var stored = (await _factory.AdminStore.GetAdminAsync("must-change", Ct))!;
        Assert.False(stored.MustChangePassword);
        Assert.True(PasswordHasher.Verify("Brand-New-Password-1", stored.PasswordHash));
    }

    [Fact]
    public void The_circuit_revalidates_its_login()
    {
        using var scope = _factory.Services.CreateScope();

        Assert.IsType<AdminRevalidatingAuthenticationStateProvider>(scope.ServiceProvider.GetRequiredService<AuthenticationStateProvider>());
    }

    private static Task<HttpResponseMessage> PostChangePasswordAsync(HttpClient browser, string token, string current, string next, string? returnUrl = null) =>
        browser.PostAsync(returnUrl is null ? "/ChangePassword" : "/ChangePassword?ReturnUrl=" + Uri.EscapeDataString(returnUrl),
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["CurrentPassword"] = current,
                ["NewPassword"] = next,
                ["RepeatPassword"] = next,
                ["__RequestVerificationToken"] = token,
            }), Ct);

    private static string ExtractToken(string html) =>
        WebUtility.HtmlDecode(AntiforgeryTokenRegex().Match(html).Groups[1].Value);

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryTokenRegex();
}

/// <summary>The upgrade path: an installation with only the configured AdminAuth account (#60).</summary>
[Collection(AdminUiCollection.Name)]
public sealed class AdminBootstrapTests : IClassFixture<AdminUiFactory>
{
    private readonly AdminUiFactory _factory;

    public AdminBootstrapTests(AdminUiFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task The_configured_account_is_imported_once_as_super_admin_and_the_same_login_works()
    {
        using var browser = _factory.CreateBrowser();

        var login = await AdminUiAuthenticationTests.LogInAsync(browser, AdminUiFactory.AdminUserName, AdminUiFactory.AdminPassword);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);

        var admin = Assert.Single(await _factory.AdminStore.ListAdminsAsync(TestContext.Current.CancellationToken));
        Assert.Equal(AdminUiFactory.AdminUserName, admin.Username);
        Assert.Equal(AdminPermissionRules.Everything, AdminPermissionRules.Effective(admin));
        Assert.NotNull(admin.LastLoginAt);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/admins", TestContext.Current.CancellationToken)).StatusCode);
    }
}

/// <summary>An installation without AdminAuth whose administrator was created with --create-admin.</summary>
public sealed class StoredAdminOnlyUiFactory : AdminUiFactory
{
    protected override bool ConfigureAdminCredential => false;

    public StoredAdminOnlyUiFactory()
    {
        AdminStore.AddAdminAsync(new Admin
        {
            Username = "created",
            PasswordHash = StoredAdminsUiFactory.Hash,
            Permissions = AdminPermissions.SuperAdmin,
        }, CancellationToken.None).GetAwaiter().GetResult();
    }
}

[Collection(AdminUiCollection.Name)]
public sealed class StoredAdminOnlyTests : IClassFixture<StoredAdminOnlyUiFactory>
{
    private readonly StoredAdminOnlyUiFactory _factory;

    public StoredAdminOnlyTests(StoredAdminOnlyUiFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task The_ui_is_open_without_admin_auth_when_an_administrator_is_stored()
    {
        using var browser = _factory.CreateBrowser();

        var login = await AdminUiAuthenticationTests.LogInAsync(browser, "created", StoredAdminsUiFactory.Password);

        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/general", TestContext.Current.CancellationToken)).StatusCode);
    }
}
