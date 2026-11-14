using System.Net;
using System.Net.Http.Json;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Security;
using FreeSftpSharp.Tests.WebUi;

namespace FreeSftpSharp.Tests.Api;

/// <summary>/api/v1/users over the services of the Users page, with the scope of the caller (#60).</summary>
[Collection(AdminUiCollection.Name)]
public sealed class ApiUsersTests : IClassFixture<ApiFactory>, IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly ApiFactory _factory;
    private readonly TempDirectory _root = new();

    public ApiUsersTests(ApiFactory factory)
    {
        _factory = factory;
    }

    public void Dispose() => _root.Dispose();

    [Fact]
    public async Task A_user_is_created_read_patched_and_deleted()
    {
        using var client = await _factory.SuperAdminAsync();

        var created = await client.PostAsJsonAsync("/api/v1/users", new
        {
            username = "api-alice",
            rootDirectory = _root.Path,
            password = "long-enough-1",
            permissions = new Dictionary<string, string[]> { ["/"] = ["List", "Download"], ["/in"] = ["All"] },
            whitelistedIps = new[] { "10.0.0.0/8" },
        }, Ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal("/api/v1/users/api-alice", created.Headers.Location!.OriginalString);
        var body = await created.JsonAsync();
        Assert.True(body["hasPassword"]!.GetValue<bool>());
        Assert.Null(body["password"]);
        Assert.DoesNotContain("hashedPassword", body.ToJsonString(), StringComparison.OrdinalIgnoreCase);

        var stored = _factory.Repository.GetUser("api-alice");
        Assert.True(PasswordHasher.Verify("long-enough-1", stored.HashedPassword));
        Assert.Equal(SshServer.Interfaces.Permissions.FilePermissions.List | SshServer.Interfaces.Permissions.FilePermissions.Download, stored.Permissions!["/"]);

        var patched = await client.PatchJsonAsync("/api/v1/users/api-alice", new { onlyWhitelistedIps = true });
        Assert.Equal(HttpStatusCode.OK, patched.StatusCode);
        stored = _factory.Repository.GetUser("api-alice");
        Assert.True(stored.OnlyWhitelistedIps);
        Assert.Equal(["10.0.0.0/8"], stored.WhitelistedIps);
        Assert.True(PasswordHasher.Verify("long-enough-1", stored.HashedPassword)); // the password stays

        var list = await (await client.GetAsync("/api/v1/users?search=api-al&limit=10", Ct)).JsonAsync();
        Assert.Equal(1, list["total"]!.GetValue<int>());

        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync("/api/v1/users/api-alice", Ct)).StatusCode);
        Assert.Null(_factory.Repository.GetUser("api-alice"));
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/v1/users/api-alice", Ct)).StatusCode);
    }

    [Fact]
    public async Task Invalid_input_is_a_validation_problem_by_field()
    {
        using var client = await _factory.SuperAdminAsync();

        var response = await client.PostAsJsonAsync("/api/v1/users", new
        {
            username = "bad name",
            password = "short",
            allowedAuthMethods = new[] { "telepathy" },
            whitelistedIps = new[] { "not-a-network" },
        }, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType!.MediaType);
        var errors = (await response.JsonAsync())["errors"]!.AsObject();
        foreach (var field in new[] { "username", "password", "allowedAuthMethods", "whitelistedIps", "rootDirectory" })
            Assert.True(errors.ContainsKey(field), field);
        Assert.Null(_factory.Repository.GetUser("bad name"));
    }

    [Fact]
    public async Task Public_keys_are_added_listed_and_removed()
    {
        using var client = await _factory.SuperAdminAsync();
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsJsonAsync("/api/v1/users", new { username = "api-keys", rootDirectory = _root.Path }, Ct)).StatusCode);

        var added = await client.PostAsJsonAsync("/api/v1/users/api-keys/public-keys", new { keys = TestUserKeys.Ed25519().AuthorizedKeysLine }, Ct);
        Assert.Equal(1, (await added.JsonAsync())["added"]!.GetValue<int>());

        var keys = await (await client.GetAsync("/api/v1/users/api-keys/public-keys", Ct)).ArrayAsync();
        var fingerprint = Assert.Single(keys)!["fingerprint"]!.GetValue<string>();

        var generated = await (await client.PostAsJsonAsync("/api/v1/users/api-keys/public-keys/generate", new { type = "ed25519" }, Ct)).JsonAsync();
        Assert.StartsWith("-----BEGIN OPENSSH PRIVATE KEY-----", generated["privateKey"]!.GetValue<string>());
        Assert.Equal(2, _factory.Repository.GetUser("api-keys").PublicKeys!.Count);

        var removed = await client.DeleteAsync("/api/v1/users/api-keys/public-keys?fingerprint=" + Uri.EscapeDataString(fingerprint), Ct);
        Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);
        Assert.DoesNotContain(_factory.Repository.GetUser("api-keys").PublicKeys!, k => k.Fingerprint == fingerprint);
    }

    [Fact]
    public async Task A_scoped_administrator_sees_and_changes_only_the_users_of_its_role()
    {
        var tenantA = await _factory.AddRoleAsync("api-tenant-a");
        var tenantB = await _factory.AddRoleAsync("api-tenant-b");
        _factory.Repository.AddUser(new User { Username = "scope-a", UserRootDirectory = _root.Path, RoleId = tenantA });
        _factory.Repository.AddUser(new User { Username = "scope-b", UserRootDirectory = _root.Path, RoleId = tenantB });
        await _factory.AddAdminAsync("tenant-a-admin", AdminPermissions.ManageUsers, tenantA);
        using var client = await _factory.ClientAsync("tenant-a-admin");

        var list = await (await client.GetAsync("/api/v1/users", Ct)).JsonAsync();
        var names = list["items"]!.AsArray().Select(u => u!["username"]!.GetValue<string>()).ToList();
        Assert.Equal(["scope-a"], names);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/v1/users/scope-b", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PatchJsonAsync("/api/v1/users/scope-b", new { rootDirectory = "/elsewhere" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.DeleteAsync("/api/v1/users/scope-b", Ct)).StatusCode);
        Assert.NotNull(_factory.Repository.GetUser("scope-b"));

        var own = await client.PostAsJsonAsync("/api/v1/users", new { username = "scope-new", rootDirectory = _root.Path }, Ct);
        Assert.Equal(HttpStatusCode.Created, own.StatusCode);
        Assert.Equal(tenantA, _factory.Repository.GetUser("scope-new").RoleId);
        var other = await client.PostAsJsonAsync("/api/v1/users", new { username = "scope-other", rootDirectory = _root.Path, roleId = tenantB }, Ct);
        Assert.Equal(HttpStatusCode.Forbidden, other.StatusCode);

        var moved = await client.PatchJsonAsync("/api/v1/users/scope-a", new { roleId = tenantB });
        Assert.Equal(HttpStatusCode.OK, moved.StatusCode);
        Assert.Equal(tenantA, _factory.Repository.GetUser("scope-a").RoleId);
    }

    [Fact]
    public async Task An_administrator_without_ManageUsers_gets_403()
    {
        await _factory.AddAdminAsync("viewer-only", AdminPermissions.ViewConnections);
        using var client = await _factory.ClientAsync("viewer-only");

        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/users", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/api/v1/users", new { username = "x", rootDirectory = _root.Path }, Ct)).StatusCode);
    }
}
