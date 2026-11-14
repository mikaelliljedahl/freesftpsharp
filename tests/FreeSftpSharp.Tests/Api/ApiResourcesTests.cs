using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using FreeSftpSharp.Tests.Settings;
using SshServer.Interfaces.Admins;
using FreeSftpSharp.Tests.WebUi;

namespace FreeSftpSharp.Tests.Api;

/// <summary>One test per resource of the REST API: the same operations as the admin UI pages.</summary>
[Collection(AdminUiCollection.Name)]
public sealed class ApiResourcesTests : IClassFixture<ApiFactory>, IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly ApiFactory _factory;
    private readonly TempDirectory _root = new();

    public ApiResourcesTests(ApiFactory factory)
    {
        _factory = factory;
    }

    public void Dispose() => _root.Dispose();

    [Fact]
    public async Task Virtual_folders_are_managed_and_their_secrets_are_write_only()
    {
        using var client = await _factory.SuperAdminAsync();

        var providers = await (await client.GetAsync("/api/v1/storage-providers", Ct)).ArrayAsync();
        Assert.Contains(providers, p => p!["name"]!.GetValue<string>() == "s3");

        var created = await client.PostAsJsonAsync("/api/v1/virtual-folders", new
        {
            name = "api-shared",
            description = "shared files",
            storage = new { provider = "local", options = new Dictionary<string, object> { ["RootDirectory"] = _root.Path } },
        }, Ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var folder = await created.JsonAsync();
        var id = folder["id"]!.GetValue<int>();
        Assert.Equal("local", folder["storage"]!["provider"]!.GetValue<string>());

        var s3 = await client.PutAsJsonAsync($"/api/v1/virtual-folders/{id}", new
        {
            name = "api-shared",
            storage = new
            {
                provider = "s3",
                options = new Dictionary<string, object> { ["Bucket"] = "bucket", ["Region"] = "eu-north-1", ["AccessKey"] = "AKIATEST", ["SecretKey"] = "very-secret-value" },
            },
        }, Ct);
        Assert.Equal(HttpStatusCode.OK, s3.StatusCode);
        var text = await s3.Content.ReadAsStringAsync(Ct);
        Assert.DoesNotContain("very-secret-value", text);
        Assert.Contains("SecretKey", (await client.GetFromJsonAsync<JsonObject>($"/api/v1/virtual-folders/{id}", Ct))!["storage"]!["storedSecrets"]!.ToJsonString());
        Assert.DoesNotContain("very-secret-value", _factory.Repository.GetVirtualFolder(id)!.Storage.Options);

        // A patch without the secret keeps it.
        Assert.Equal(HttpStatusCode.OK, (await client.PatchJsonAsync($"/api/v1/virtual-folders/{id}", new { description = "changed" })).StatusCode);
        var view = (await client.GetFromJsonAsync<JsonObject>($"/api/v1/virtual-folders/{id}", Ct))!;
        Assert.Equal("changed", view["description"]!.GetValue<string>());
        Assert.Contains("SecretKey", view["storage"]!["storedSecrets"]!.ToJsonString());

        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/api/v1/virtual-folders/{id}", Ct)).StatusCode);
        Assert.Null(_factory.Repository.GetVirtualFolder(id));
    }

    [Fact]
    public async Task Administrators_and_roles_are_managed_without_privilege_escalation()
    {
        using var client = await _factory.SuperAdminAsync();

        var role = await (await client.PostAsJsonAsync("/api/v1/roles", new { name = "api-role", description = "a tenant" }, Ct)).JsonAsync();
        var roleId = role["id"]!.GetValue<int>();
        var created = await client.PostAsJsonAsync("/api/v1/admins", new
        {
            username = "api-helper", password = "helper-password-1", permissions = new[] { "ManageUsers", "ManageAdmins" },
        }, Ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Null((await created.JsonAsync())["passwordHash"]);

        var patched = await client.PatchJsonAsync("/api/v1/admins/api-helper", new { email = "helper@example.com" });
        Assert.Equal(HttpStatusCode.OK, patched.StatusCode);
        Assert.Equal("helper@example.com", (await _factory.Admins.GetAdminAsync("api-helper", Ct))!.Email);

        using var helper = _factory.BearerClient(await _factory.TokenAsync("api-helper", "helper-password-1"));
        var escalation = await helper.PostAsJsonAsync("/api/v1/admins", new { username = "api-root", password = "root-password-1", permissions = new[] { "SuperAdmin" } }, Ct);
        Assert.Equal(HttpStatusCode.Forbidden, escalation.StatusCode);
        Assert.Null(await _factory.Admins.GetAdminAsync("api-root", Ct));

        Assert.Equal(HttpStatusCode.OK, (await client.PutAsJsonAsync($"/api/v1/roles/{roleId}", new { name = "api-role-2" }, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/api/v1/roles/{roleId}", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync("/api/v1/admins/api-helper", Ct)).StatusCode);
    }

    [Fact]
    public async Task An_administrator_of_the_single_sign_on_gets_no_password()
    {
        using var client = await _factory.SuperAdminAsync();
        var sso = await _factory.AddAdminAsync("api-sso", AdminPermissions.ViewAudit);
        sso.AuthenticationProvider = "oidc";
        Assert.True(await _factory.Admins.UpdateAdminAsync(sso, Ct));

        var view = await (await client.GetAsync("/api/v1/admins/api-sso", Ct)).JsonAsync();
        Assert.Equal("oidc", view["authenticationProvider"]!.GetValue<string>());

        var patched = await client.PatchJsonAsync("/api/v1/admins/api-sso", new { password = "new-password-123" });
        Assert.Equal(HttpStatusCode.BadRequest, patched.StatusCode);
        Assert.Contains("managed by oidc", await patched.Content.ReadAsStringAsync(Ct));
        Assert.Equal(sso.PasswordHash, (await _factory.Admins.GetAdminAsync("api-sso", Ct))!.PasswordHash);
        Assert.Equal(HttpStatusCode.OK, (await client.PatchJsonAsync("/api/v1/admins/api-sso", new { email = "sso@example.com" })).StatusCode);
    }

    [Fact]
    public async Task Connections_audit_and_ip_bans_are_readable()
    {
        await _factory.AddAdminAsync("monitor", AdminPermissions.ViewConnections | AdminPermissions.DisconnectConnections | AdminPermissions.ViewAudit);
        using var client = await _factory.ClientAsync("monitor");

        var connections = await (await client.GetAsync("/api/v1/connections", Ct)).JsonAsync();
        Assert.Equal(0, connections["total"]!.GetValue<int>());
        Assert.Equal(HttpStatusCode.NotFound, (await client.DeleteAsync($"/api/v1/connections/{Guid.NewGuid()}", Ct)).StatusCode);

        var audit = await client.GetAsync("/api/v1/audit?type=LoginOk&limit=5", Ct);
        Assert.Equal(HttpStatusCode.OK, audit.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/api/v1/audit?limit=0", Ct)).StatusCode);

        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/ip-bans", Ct)).StatusCode);
        using var admin = await _factory.SuperAdminAsync();
        Assert.Empty(await (await admin.GetAsync("/api/v1/ip-bans", Ct)).ArrayAsync());
        Assert.Equal(HttpStatusCode.NotFound, (await admin.DeleteAsync("/api/v1/ip-bans/192.0.2.7", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.DeleteAsync("/api/v1/ip-bans/not-an-ip", Ct)).StatusCode);
    }

    [Fact]
    public async Task Webhooks_are_managed_and_the_secret_is_write_only()
    {
        using var client = await _factory.SuperAdminAsync();

        var created = await client.PostAsJsonAsync("/api/v1/webhooks", new
        {
            name = "api-hook", url = "http://127.0.0.1:9/hook", secret = "hook-secret-value", eventTypes = new[] { "File.Upload" },
        }, Ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var hook = await created.JsonAsync();
        Assert.True(hook["hasSecret"]!.GetValue<bool>());
        Assert.DoesNotContain("hook-secret-value", hook.ToJsonString());
        var id = hook["id"]!.GetValue<int>();

        Assert.Equal(HttpStatusCode.OK, (await client.PatchJsonAsync($"/api/v1/webhooks/{id}", new { enabled = false })).StatusCode);
        var view = (await client.GetFromJsonAsync<JsonObject>($"/api/v1/webhooks/{id}", Ct))!;
        Assert.False(view["enabled"]!.GetValue<bool>());
        Assert.True(view["hasSecret"]!.GetValue<bool>());

        var invalid = await client.PostAsJsonAsync("/api/v1/webhooks", new { name = "bad-hook", url = "ftp://example.com" }, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/api/v1/webhooks/{id}", Ct)).StatusCode);
    }

    [Fact]
    public async Task Settings_are_read_by_every_administrator_and_changed_with_ManageSettings()
    {
        await _factory.AddAdminAsync("settings-reader", AdminPermissions.ViewAudit);
        using var reader = await _factory.ClientAsync("settings-reader");
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync("/api/v1/settings", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.PatchJsonAsync("/api/v1/settings", new { serverBanner = "x" })).StatusCode);

        using var admin = await _factory.SuperAdminAsync();
        var saved = await admin.PutAsJsonAsync("/api/v1/settings", new { serverBanner = "Welcome", idleTimeout = 120 }, Ct);
        Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
        Assert.Equal("Welcome", _factory.Repository.ServerSettings.ServerBanner);
        Assert.Equal(120, _factory.Repository.ServerSettings.IdleTimeout);
        var view = await saved.JsonAsync();
        Assert.DoesNotContain("BEGIN", view.ToJsonString());

        var invalid = await admin.PutAsJsonAsync("/api/v1/settings", new { listenToPort = 70000 }, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        Assert.True((await invalid.JsonAsync())["errors"]!.AsObject().ContainsKey("listenToPort"));
    }
}
