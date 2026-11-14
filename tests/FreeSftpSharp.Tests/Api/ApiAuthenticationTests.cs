using System.Net;
using System.Net.Http.Json;
using FreeSftpSharp.Tests.WebUi;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Api.ApiKeys;
using SshServer.Api.Authentication;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Api;

namespace FreeSftpSharp.Tests.Api;

/// <summary>Bearer tokens and API keys of the REST API (#67): who gets in, and with which permissions.</summary>
[Collection(AdminUiCollection.Name)]
public sealed class ApiAuthenticationTests : IClassFixture<ApiFactory>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly ApiFactory _factory;

    public ApiAuthenticationTests(ApiFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Health_answers_without_login_and_everything_else_needs_one()
    {
        using var client = _factory.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/health", Ct)).StatusCode);
        foreach (var path in new[] { "/api/v1/status", "/api/v1/users", "/api/v1/settings", "/api/v1/openapi.json", "/api/v1/dump", "/api/v1/no-such-route" })
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync(path, Ct)).StatusCode);
    }

    [Fact]
    public async Task A_token_from_the_admin_credentials_signs_in()
    {
        using var client = await _factory.SuperAdminAsync();

        var status = await (await client.GetAsync("/api/v1/status", Ct)).JsonAsync();

        Assert.Equal(AdminUiFactory.AdminUserName, status["administrator"]!.GetValue<string>());
        Assert.Contains("SuperAdmin", status["permissions"]!.AsArray().Select(p => p!.GetValue<string>()));
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/v1/no-such-route", Ct)).StatusCode);
    }

    [Fact]
    public async Task A_wrong_password_gets_no_token_and_is_in_the_audit_log()
    {
        using var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/token", new { username = AdminUiFactory.AdminUserName, password = "wrong-password" }, Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType!.MediaType);
        await WaitForAuditAsync(e => e.Type == "LoginFailed" && e.Protocol == "API" && e.Username == AdminUiFactory.AdminUserName);
    }

    [Fact]
    public async Task An_invalid_or_expired_token_is_refused()
    {
        var admin = (await _factory.Admins.GetAdminAsync(AdminUiFactory.AdminUserName, Ct))!;
        var tokens = _factory.Services.GetRequiredService<ApiTokenService>();
        var expired = tokens.Issue(admin, DateTimeOffset.UtcNow.AddHours(-2)).AccessToken;
        var valid = tokens.Issue(admin).AccessToken;

        using (var client = _factory.BearerClient(expired))
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/status", Ct)).StatusCode);
        using (var client = _factory.BearerClient(valid[..^4] + "AAAA"))
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/status", Ct)).StatusCode);
        using (var client = _factory.BearerClient(valid))
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/status", Ct)).StatusCode);
    }

    [Fact]
    public async Task A_token_ends_when_the_administrator_changes()
    {
        await _factory.AddAdminAsync("changing-admin", AdminPermissions.ManageUsers);
        using var client = await _factory.ClientAsync("changing-admin");
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/users", Ct)).StatusCode);

        var stored = (await _factory.Admins.GetAdminAsync("changing-admin", Ct))!;
        stored.Status = AdminStatus.Disabled;
        Assert.True(await _factory.Admins.UpdateAdminAsync(stored, Ct));

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/users", Ct)).StatusCode);
    }

    [Fact]
    public async Task The_login_cookie_of_the_admin_UI_is_not_accepted_by_the_API()
    {
        using var browser = _factory.CreateBrowser();
        var login = await AdminUiAuthenticationTests.LogInAsync(browser, AdminUiFactory.AdminUserName, AdminUiFactory.AdminPassword);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/", Ct)).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/v1/status", Ct)).StatusCode);
    }

    [Fact]
    public async Task An_api_key_acts_as_its_administrator_and_is_shown_once()
    {
        await _factory.AddAdminAsync("key-owner", AdminPermissions.ManageUsers);
        using var owner = await _factory.ClientAsync("key-owner");

        var key = await ApiFactory.CreateApiKeyAsync(owner, "deploy");
        using var client = _factory.ApiKeyClient(key);

        var status = await (await client.GetAsync("/api/v1/status", Ct)).JsonAsync();
        Assert.Equal("key-owner (API key deploy)", status["administrator"]!.GetValue<string>());
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/users", Ct)).StatusCode);

        var listed = await (await owner.GetAsync("/api/v1/api-keys", Ct)).ArrayAsync();
        var entry = Assert.Single(listed);
        Assert.Equal("deploy", entry!["name"]!.GetValue<string>());
        Assert.Null(entry["key"]);
        Assert.DoesNotContain(key, entry.ToJsonString());
        var stored = Assert.Single(await _factory.ApiKeys.ListAsync(null, Ct), k => k.Name == "deploy");
        Assert.Equal(ApiKeyService.Hash(key), stored.KeyHash);
    }

    [Fact]
    public async Task An_api_key_bound_to_a_user_manager_cannot_change_settings()
    {
        await _factory.AddAdminAsync("user-manager", AdminPermissions.ManageUsers);
        using var owner = await _factory.ClientAsync("user-manager");
        using var client = _factory.ApiKeyClient(await ApiFactory.CreateApiKeyAsync(owner, "provisioning"));

        var response = await client.PutAsJsonAsync("/api/v1/settings", new { serverBanner = "changed" }, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.NotEqual("changed", _factory.Repository.ServerSettings.ServerBanner);
    }

    [Fact]
    public async Task The_scopes_of_an_api_key_narrow_its_permissions()
    {
        await _factory.AddAdminAsync("auditor", AdminPermissions.ManageUsers | AdminPermissions.ViewAudit);
        using var owner = await _factory.ClientAsync("auditor");
        using var client = _factory.ApiKeyClient(await ApiFactory.CreateApiKeyAsync(owner, "audit-only", "ViewAudit"));

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/audit", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/users", Ct)).StatusCode);

        var tooMuch = await owner.PostAsJsonAsync("/api/v1/api-keys", new { name = "more", scopes = new[] { "ManageSettings" } }, Ct);
        Assert.Equal(HttpStatusCode.Forbidden, tooMuch.StatusCode);
    }

    [Fact]
    public async Task An_api_key_cannot_create_keys_and_a_revoked_or_expired_key_is_refused()
    {
        await _factory.AddAdminAsync("revoker", AdminPermissions.ManageUsers);
        using var owner = await _factory.ClientAsync("revoker");
        var key = await ApiFactory.CreateApiKeyAsync(owner, "short-lived");
        using var client = _factory.ApiKeyClient(key);

        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/api/v1/api-keys", new { name = "child" }, Ct)).StatusCode);

        var id = (await _factory.ApiKeys.FindByHashAsync(ApiKeyService.Hash(key), Ct))!.Id;
        Assert.Equal(HttpStatusCode.NoContent, (await owner.DeleteAsync($"/api/v1/api-keys/{id}", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/status", Ct)).StatusCode);

        var revoker = (await _factory.Admins.GetAdminAsync("revoker", Ct))!;
        const string expiredKey = ApiKeyService.KeyPrefix + "expired-key-for-the-test";
        Assert.True(await _factory.ApiKeys.AddAsync(new ApiKey
        {
            Name = "expired", Prefix = expiredKey[..12], KeyHash = ApiKeyService.Hash(expiredKey), AdminId = revoker.Id,
            CreatedAt = DateTime.UtcNow.AddDays(-2), ExpiresAt = DateTime.UtcNow.AddDays(-1),
        }, Ct));
        using var expired = _factory.ApiKeyClient(expiredKey);
        Assert.Equal(HttpStatusCode.Unauthorized, (await expired.GetAsync("/api/v1/status", Ct)).StatusCode);
        using var unknown = _factory.ApiKeyClient(ApiKeyService.KeyPrefix + "unknown");
        Assert.Equal(HttpStatusCode.Unauthorized, (await unknown.GetAsync("/api/v1/status", Ct)).StatusCode);
    }

    [Fact]
    public async Task Changes_with_an_api_key_are_in_the_audit_log_with_the_key_name()
    {
        await _factory.AddAdminAsync("role-manager", AdminPermissions.ManageAdmins);
        using var owner = await _factory.ClientAsync("role-manager");
        using var client = _factory.ApiKeyClient(await ApiFactory.CreateApiKeyAsync(owner, "terraform"));

        var response = await client.PostAsJsonAsync("/api/v1/roles", new { name = "audited-role" }, Ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        await WaitForAuditAsync(e => e.Path == "Role/audited-role" && e.Actor == "role-manager (API key terraform)");
        await WaitForAuditAsync(e => e.Path == "ApiKey/role-manager/terraform" && e.Type == "Add" && e.Actor == "role-manager");
    }

    private async Task WaitForAuditAsync(Func<SshServer.Interfaces.Audit.AuditEntry, bool> match)
    {
        // The audit sink writes in the background.
        for (var i = 0; i < 100; i++)
        {
            var entries = await _factory.Audit.QueryAsync(new SshServer.Interfaces.Audit.AuditQuery { Take = 1000 }, Ct);
            if (entries.Entries.Any(match))
                return;
            await Task.Delay(50, Ct);
        }
        Assert.Fail("The audit log has no matching entry.");
    }
}

/// <summary>Without Api:Enabled the routes do not exist.</summary>
[Collection(AdminUiCollection.Name)]
public sealed class ApiDisabledTests : IClassFixture<AdminUiFactory>
{
    private readonly AdminUiFactory _factory;

    public ApiDisabledTests(AdminUiFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task The_api_is_off_by_default()
    {
        using var client = _factory.CreateBrowser();

        var response = await client.PostAsJsonAsync("/api/v1/token",
            new { username = AdminUiFactory.AdminUserName, password = AdminUiFactory.AdminPassword }, TestContext.Current.CancellationToken);

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(_factory.Services.GetService<ApiTokenService>());
    }
}
