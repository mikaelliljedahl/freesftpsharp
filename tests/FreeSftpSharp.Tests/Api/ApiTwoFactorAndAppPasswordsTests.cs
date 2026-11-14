using System.Net;
using System.Net.Http.Json;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using FreeSftpSharp.Tests.WebUi;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.TwoFactor;
using SshServer.TwoFactor;

namespace FreeSftpSharp.Tests.Api;

/// <summary>The allowed protocols (#71), the app passwords (#71) and the second factor (#63) of users and administrators through /api/v1.</summary>
[Collection(AdminUiCollection.Name)]
public sealed class ApiTwoFactorAndAppPasswordsTests : IClassFixture<ApiFactory>, IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly ApiFactory _factory;
    private readonly TempDirectory _root = new();

    public ApiTwoFactorAndAppPasswordsTests(ApiFactory factory)
    {
        _factory = factory;
    }

    public void Dispose() => _root.Dispose();

    private TwoFactorService TwoFactor => _factory.Services.GetRequiredService<TwoFactorService>();

    private User AddUser(string name, string? provider = null)
    {
        var user = new User { Username = name, UserRootDirectory = _root.Path, AuthenticationProvider = provider };
        Assert.True(_factory.Repository.AddUser(user));
        return _factory.Repository.GetUser(name);
    }

    [Fact]
    public async Task The_allowed_protocols_are_read_written_patched_and_validated()
    {
        using var client = await _factory.SuperAdminAsync();
        var created = await (await client.PostAsJsonAsync("/api/v1/users", new { username = "proto-user", rootDirectory = _root.Path }, Ct)
            .ExpectAsync(HttpStatusCode.Created)).JsonAsync();
        Assert.Equal(["sftp", "webdav", "web", "ftp"], created["allowedProtocols"]!.AsArray().Select(p => p!.GetValue<string>()));

        await client.PatchJsonAsync("/api/v1/users/proto-user", new { allowedProtocols = new[] { "SFTP", "webdav" } }).ExpectAsync(HttpStatusCode.OK);
        Assert.Equal(UserProtocols.Sftp | UserProtocols.WebDav, _factory.Repository.GetUser("proto-user").AllowedProtocols);

        // Another patch keeps them; a PUT without the field gives the default (all).
        await client.PatchJsonAsync("/api/v1/users/proto-user", new { description = "x" }).ExpectAsync(HttpStatusCode.OK);
        Assert.Equal(UserProtocols.Sftp | UserProtocols.WebDav, _factory.Repository.GetUser("proto-user").AllowedProtocols);
        var view = await (await client.GetAsync("/api/v1/users/proto-user", Ct)).JsonAsync();
        Assert.Equal(["sftp", "webdav"], view["allowedProtocols"]!.AsArray().Select(p => p!.GetValue<string>()));
        await client.PutAsJsonAsync("/api/v1/users/proto-user", new { rootDirectory = _root.Path }, Ct).ExpectAsync(HttpStatusCode.OK);
        Assert.Equal(UserProtocols.All, _factory.Repository.GetUser("proto-user").AllowedProtocols);

        foreach (var invalid in new[] { new[] { "telnet" }, Array.Empty<string>() })
        {
            var response = await client.PatchJsonAsync("/api/v1/users/proto-user", new { allowedProtocols = invalid });
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.True((await response.JsonAsync())["errors"]!.AsObject().ContainsKey("allowedProtocols"));
        }
        Assert.Equal(UserProtocols.All, _factory.Repository.GetUser("proto-user").AllowedProtocols);
    }

    [Fact]
    public async Task An_app_password_is_created_listed_without_its_secret_and_revoked()
    {
        AddUser("app-user");
        using var client = await _factory.SuperAdminAsync();

        var response = await client.PostAsJsonAsync("/api/v1/users/app-user/app-passwords",
            new { name = "Laptop", protocols = new[] { "webdav", "ftp" }, expiresAt = DateTime.UtcNow.AddDays(30) }, Ct).ExpectAsync(HttpStatusCode.Created);
        Assert.Equal("no-store", response.Headers.CacheControl!.ToString());
        var created = await response.JsonAsync();
        var secret = created["secret"]!.GetValue<string>();
        var id = created["appPassword"]!["id"]!.GetValue<string>();
        Assert.False(string.IsNullOrEmpty(secret));
        Assert.Equal(["webdav", "ftp"], created["appPassword"]!["protocols"]!.AsArray().Select(p => p!.GetValue<string>()));

        // The server keeps only the hash, and the secret is in no later response.
        var stored = Assert.Single(_factory.Repository.GetUser("app-user").AppPasswords!);
        Assert.NotEqual(secret, stored.SecretHash);
        Assert.True(stored.Matches(secret));
        var listResponse = await client.GetAsync("/api/v1/users/app-user/app-passwords", Ct).ExpectAsync(HttpStatusCode.OK);
        var listText = await listResponse.Content.ReadAsStringAsync(Ct);
        Assert.DoesNotContain(secret, listText, StringComparison.Ordinal);
        Assert.DoesNotContain("secret", listText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SHA256", listText, StringComparison.Ordinal);
        var item = Assert.Single(System.Text.Json.Nodes.JsonNode.Parse(listText)!.AsArray())!;
        Assert.Equal(id, item["id"]!.GetValue<string>());
        Assert.Equal("Laptop", item["name"]!.GetValue<string>());
        Assert.False(item["expired"]!.GetValue<bool>());
        Assert.DoesNotContain(secret, await (await client.GetAsync("/api/v1/users/app-user", Ct)).Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);

        // The same name, an unknown protocol and an expiry in the past are refused.
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/v1/users/app-user/app-passwords", new { name = "laptop" }, Ct)).StatusCode);
        var unknown = await client.PostAsJsonAsync("/api/v1/users/app-user/app-passwords", new { name = "Other", protocols = new[] { "gopher" } }, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        Assert.True((await unknown.JsonAsync())["errors"]!.AsObject().ContainsKey("protocols"));
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/v1/users/app-user/app-passwords",
            new { name = "Old", expiresAt = DateTime.UtcNow.AddDays(-1) }, Ct)).StatusCode);

        Assert.Equal(HttpStatusCode.NotFound, (await client.DeleteAsync("/api/v1/users/app-user/app-passwords/nope", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/api/v1/users/app-user/app-passwords/{id}", Ct)).StatusCode);
        Assert.Empty(_factory.Repository.GetUser("app-user").AppPasswords ?? []);
        Assert.Empty(await (await client.GetAsync("/api/v1/users/app-user/app-passwords", Ct)).ArrayAsync());
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/v1/users/no-such-user/app-passwords", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsJsonAsync("/api/v1/users/no-such-user/app-passwords", new { name = "x" }, Ct)).StatusCode);
    }

    [Fact]
    public async Task An_app_password_is_allowed_for_a_user_of_an_external_provider_as_in_the_Users_page()
    {
        AddUser("app-ldap-user", "ldap");
        using var client = await _factory.SuperAdminAsync();

        var response = await client.PostAsJsonAsync("/api/v1/users/app-ldap-user/app-passwords", new { name = "WebDAV client" }, Ct).ExpectAsync(HttpStatusCode.Created);

        var created = await response.JsonAsync();
        Assert.Equal(["webdav"], created["appPassword"]!["protocols"]!.AsArray().Select(p => p!.GetValue<string>()));
        Assert.Single(_factory.Repository.GetUser("app-ldap-user").AppPasswords!);
    }

    [Fact]
    public async Task The_second_factor_of_a_user_is_read_and_reset_and_never_shows_a_secret()
    {
        var user = AddUser("tf-user");
        using var client = await _factory.SuperAdminAsync();

        var off = await (await client.GetAsync("/api/v1/users/tf-user/two-factor", Ct).ExpectAsync(HttpStatusCode.OK)).JsonAsync();
        Assert.False(off["enrolled"]!.GetValue<bool>());
        Assert.Equal("Off", off["state"]!.GetValue<string>());
        Assert.Equal(HttpStatusCode.NotFound, (await client.DeleteAsync("/api/v1/users/tf-user/two-factor", Ct)).StatusCode);

        var (secret, recoveryCodes) = await TwoFactorTestKit.EnrolAsync(TwoFactor, TwoFactorSubject.ForUser(user), TimeProvider.System, "tf-user");
        var response = await client.GetAsync("/api/v1/users/tf-user/two-factor", Ct).ExpectAsync(HttpStatusCode.OK);
        var text = await response.Content.ReadAsStringAsync(Ct);
        Assert.DoesNotContain(secret, text, StringComparison.Ordinal);
        Assert.DoesNotContain(recoveryCodes[0], text, StringComparison.Ordinal);
        var on = System.Text.Json.Nodes.JsonNode.Parse(text)!;
        Assert.True(on["enrolled"]!.GetValue<bool>());
        Assert.Equal("On", on["state"]!.GetValue<string>());
        Assert.NotNull(on["createdAt"]);
        Assert.NotNull(on["enabledAt"]);
        Assert.Equal(recoveryCodes.Count, on["recoveryCodesLeft"]!.GetValue<int>());

        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync("/api/v1/users/tf-user/two-factor", Ct)).StatusCode);
        Assert.False(await TwoFactor.IsEnabledAsync(TwoFactorSubject.ForUser(user), Ct));
        Assert.Equal("Off", (await (await client.GetAsync("/api/v1/users/tf-user/two-factor", Ct)).JsonAsync())["state"]!.GetValue<string>());
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/v1/users/no-such-user/two-factor", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.DeleteAsync("/api/v1/users/no-such-user/two-factor", Ct)).StatusCode);
    }

    [Fact]
    public async Task The_second_factor_of_an_administrator_is_read_and_reset_with_ManageAdmins_and_not_for_oneself()
    {
        var other = await _factory.AddAdminAsync("tf-other", AdminPermissions.ViewConnections);
        await _factory.AddAdminAsync("tf-manager", AdminPermissions.ManageAdmins | AdminPermissions.ViewConnections);
        using var manager = await _factory.ClientAsync("tf-manager");
        var managerToken = await _factory.TokenAsync("tf-manager", ApiFactory.Password);
        await TwoFactorTestKit.EnrolAsync(TwoFactor, TwoFactorSubject.ForAdmin(other), TimeProvider.System, "tf-other");

        var status = await (await manager.GetAsync("/api/v1/admins/tf-other/two-factor", Ct).ExpectAsync(HttpStatusCode.OK)).JsonAsync();
        Assert.True(status["enrolled"]!.GetValue<bool>());
        Assert.Equal(HttpStatusCode.NoContent, (await manager.DeleteAsync("/api/v1/admins/tf-other/two-factor", Ct)).StatusCode);
        Assert.False(await TwoFactor.IsEnabledAsync(TwoFactorSubject.ForAdmin(other), Ct));
        Assert.Equal(HttpStatusCode.NotFound, (await manager.DeleteAsync("/api/v1/admins/tf-other/two-factor", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await manager.GetAsync("/api/v1/admins/nobody/two-factor", Ct)).StatusCode);

        // An administrator with permissions that the caller does not have cannot be reset by it.
        var strong = await _factory.AddAdminAsync("tf-strong", AdminPermissions.ManageAdmins | AdminPermissions.ManageUsers | AdminPermissions.ViewAudit);
        await TwoFactorTestKit.EnrolAsync(TwoFactor, TwoFactorSubject.ForAdmin(strong), TimeProvider.System, "tf-strong");
        Assert.Equal(HttpStatusCode.Forbidden, (await manager.DeleteAsync("/api/v1/admins/tf-strong/two-factor", Ct)).StatusCode);
        Assert.True(await TwoFactor.IsEnabledAsync(TwoFactorSubject.ForAdmin(strong), Ct));

        // The own second factor needs a current code, which the API does not take: use the admin UI.
        var self = await _factory.Admins.GetAdminAsync("tf-manager", Ct);
        await TwoFactorTestKit.EnrolAsync(TwoFactor, TwoFactorSubject.ForAdmin(self!), TimeProvider.System, "tf-manager");
        using var selfClient = _factory.BearerClient(managerToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await selfClient.DeleteAsync("/api/v1/admins/tf-manager/two-factor", Ct)).StatusCode);
        Assert.True(await TwoFactor.IsEnabledAsync(TwoFactorSubject.ForAdmin(self!), Ct));
    }

    [Fact]
    public async Task The_routes_need_the_role_of_the_admin_pages_and_the_scope_of_the_caller()
    {
        var tenantA = await _factory.AddRoleAsync("tf-tenant-a");
        var tenantB = await _factory.AddRoleAsync("tf-tenant-b");
        var inA = AddUser("tf-scope-a");
        var inB = AddUser("tf-scope-b");
        inA.RoleId = tenantA;
        inB.RoleId = tenantB;
        Assert.True(_factory.Repository.UpdateUser(inA));
        Assert.True(_factory.Repository.UpdateUser(inB));
        await TwoFactorTestKit.EnrolAsync(TwoFactor, TwoFactorSubject.ForUser(inB), TimeProvider.System, "tf-scope-b");
        await _factory.AddAdminAsync("tf-viewer", AdminPermissions.ViewConnections);
        await _factory.AddAdminAsync("tf-users", AdminPermissions.ManageUsers, tenantA);
        using var viewer = await _factory.ClientAsync("tf-viewer");
        using var scoped = await _factory.ClientAsync("tf-users");

        // Without ManageUsers (users) or ManageAdmins (administrators): 403, also for a user that does not exist.
        foreach (var url in new[] { "/api/v1/users/tf-scope-a/app-passwords", "/api/v1/users/tf-scope-a/two-factor", "/api/v1/admins/tf-viewer/two-factor" })
        {
            Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync(url, Ct)).StatusCode);
        }
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PostAsJsonAsync("/api/v1/users/tf-scope-a/app-passwords", new { name = "x" }, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.DeleteAsync("/api/v1/users/tf-scope-a/app-passwords/x", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.DeleteAsync("/api/v1/users/tf-scope-a/two-factor", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.DeleteAsync("/api/v1/admins/tf-viewer/two-factor", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await scoped.GetAsync("/api/v1/admins/tf-viewer/two-factor", Ct)).StatusCode);

        // A scoped administrator works on the users of its role only.
        Assert.Equal(HttpStatusCode.Created, (await scoped.PostAsJsonAsync("/api/v1/users/tf-scope-a/app-passwords", new { name = "x" }, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await scoped.GetAsync("/api/v1/users/tf-scope-a/two-factor", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await scoped.GetAsync("/api/v1/users/tf-scope-b/app-passwords", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await scoped.PostAsJsonAsync("/api/v1/users/tf-scope-b/app-passwords", new { name = "x" }, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await scoped.GetAsync("/api/v1/users/tf-scope-b/two-factor", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await scoped.DeleteAsync("/api/v1/users/tf-scope-b/two-factor", Ct)).StatusCode);
        Assert.True(await TwoFactor.IsEnabledAsync(TwoFactorSubject.ForUser(inB), Ct));
        Assert.Empty(_factory.Repository.GetUser("tf-scope-b").AppPasswords ?? []);
    }
}
