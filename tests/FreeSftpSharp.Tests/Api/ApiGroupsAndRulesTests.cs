using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using FreeSftpSharp.Tests.Settings;
using FreeSftpSharp.Tests.WebUi;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Groups;

namespace FreeSftpSharp.Tests.Api;

/// <summary>/api/v1/groups (#61), the user lifecycle fields, and /api/v1/event-rules (#68).</summary>
[Collection(AdminUiCollection.Name)]
public sealed class ApiGroupsAndRulesTests : IClassFixture<ApiFactory>, IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly ApiFactory _factory;
    private readonly TempDirectory _root = new();

    public ApiGroupsAndRulesTests(ApiFactory factory)
    {
        _factory = factory;
    }

    public void Dispose() => _root.Dispose();

    [Fact]
    public async Task Groups_are_managed_and_users_become_members()
    {
        using var client = await _factory.SuperAdminAsync();

        var created = await client.PostAsJsonAsync("/api/v1/groups", new
        {
            name = "api-staff",
            permissions = new Dictionary<string, string[]> { ["/"] = ["List", "Download"] },
            allowedIps = new[] { "10.0.0.0/8" },
            storage = new { provider = "local", options = new Dictionary<string, object> { ["RootDirectory"] = Path.Combine(_root.Path, "%username%") } },
        }, Ct).ExpectAsync(HttpStatusCode.Created);
        var id = (await created.JsonAsync())["id"]!.GetValue<int>();

        // The group gives the storage, so the user needs no root directory.
        await client.PostAsJsonAsync("/api/v1/users", new { username = "api-member", primaryGroupId = id }, Ct).ExpectAsync(HttpStatusCode.Created);
        await client.PostAsJsonAsync("/api/v1/users", new { username = "api-second", rootDirectory = _root.Path }, Ct).ExpectAsync(HttpStatusCode.Created);
        await client.PostAsJsonAsync($"/api/v1/groups/{id}/members", new { username = "api-second" }, Ct).ExpectAsync(HttpStatusCode.NoContent);

        var members = await (await client.GetAsync($"/api/v1/groups/{id}/members", Ct)).ArrayAsync();
        Assert.Equal(["api-member", "api-second"], members.Select(m => m!.GetValue<string>()));
        Assert.Equal([id], _factory.Repository.GetUser("api-second").SecondaryGroupIds);

        Assert.Equal(HttpStatusCode.Conflict, (await client.DeleteAsync($"/api/v1/groups/{id}", Ct)).StatusCode);
        await client.PatchJsonAsync($"/api/v1/groups/{id}", new { description = "the staff" }).ExpectAsync(HttpStatusCode.OK);
        Assert.Equal("the staff", _factory.Repository.GetGroup(id)!.Description);
        Assert.Equal(["10.0.0.0/8"], _factory.Repository.GetGroup(id)!.AllowedIps);

        await client.DeleteAsync($"/api/v1/groups/{id}/members/api-second", Ct).ExpectAsync(HttpStatusCode.NoContent);
        await client.DeleteAsync("/api/v1/users/api-member", Ct).ExpectAsync(HttpStatusCode.NoContent);
        await client.DeleteAsync($"/api/v1/groups/{id}", Ct).ExpectAsync(HttpStatusCode.NoContent);
        Assert.Null(_factory.Repository.GetGroup(id));
    }

    [Fact]
    public async Task A_scoped_administrator_sees_only_the_groups_of_its_role()
    {
        var roleA = await _factory.AddRoleAsync("api-group-a");
        var roleB = await _factory.AddRoleAsync("api-group-b");
        _factory.Repository.AddGroup(new Group { Name = "group-of-a", RoleId = roleA });
        _factory.Repository.AddGroup(new Group { Name = "group-of-b", RoleId = roleB });
        await _factory.AddAdminAsync("group-admin-a", AdminPermissions.ManageGroups | AdminPermissions.ManageUsers, roleA);
        using var client = await _factory.ClientAsync("group-admin-a");

        var list = await (await client.GetAsync("/api/v1/groups", Ct)).JsonAsync();
        Assert.Equal(["group-of-a"], list["items"]!.AsArray().Select(g => g!["name"]!.GetValue<string>()));
        var other = _factory.Repository.GetGroups().Single(g => g.Name == "group-of-b").Id;
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/api/v1/groups/{other}", Ct)).StatusCode);

        var created = await (await client.PostAsJsonAsync("/api/v1/groups", new { name = "new-of-a" }, Ct).ExpectAsync(HttpStatusCode.Created)).JsonAsync();
        Assert.Equal(roleA, created["roleId"]!.GetValue<int>());
    }

    [Fact]
    public async Task The_user_lifecycle_fields_are_saved()
    {
        using var client = await _factory.SuperAdminAsync();
        var expires = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        await client.PostAsJsonAsync("/api/v1/users", new
        {
            username = "api-lifecycle", rootDirectory = _root.Path, password = "lifecycle-pass-1", description = "contractor",
            status = "Disabled", expiresAt = expires, maxSessions = 2,
        }, Ct).ExpectAsync(HttpStatusCode.Created);

        var user = _factory.Repository.GetUser("api-lifecycle");
        Assert.Equal(UserStatus.Disabled, user.Status);
        Assert.Equal(expires, user.ExpiresAt);
        Assert.Equal(2, user.MaxSessions);
        Assert.Equal("contractor", user.Description);
        Assert.NotNull(user.PasswordChangedAt);
        Assert.Null(user.Permissions);

        var view = await (await client.PatchJsonAsync("/api/v1/users/api-lifecycle", new { status = "Enabled", maxSessions = 0 })
            .ExpectAsync(HttpStatusCode.OK)).JsonAsync();
        Assert.Equal("Enabled", view["status"]!.GetValue<string>());
        Assert.Equal(UserStatus.Enabled, _factory.Repository.GetUser("api-lifecycle").Status);
        Assert.Equal(expires, _factory.Repository.GetUser("api-lifecycle").ExpiresAt);

        var invalid = await client.PatchJsonAsync("/api/v1/users/api-lifecycle", new { maxSessions = -1 });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
    }

    [Fact]
    public async Task Event_rules_are_managed_and_run_on_demand()
    {
        using var client = await _factory.SuperAdminAsync();
        await client.PostAsJsonAsync("/api/v1/users", new { username = "api-rule-user", rootDirectory = _root.Path }, Ct).ExpectAsync(HttpStatusCode.Created);

        var types = await (await client.GetAsync("/api/v1/event-rules/action-types", Ct)).ArrayAsync();
        Assert.Contains(types, t => t!["type"]!.GetValue<string>() == "CreateDirectory");

        var created = await client.PostAsJsonAsync("/api/v1/event-rules", new
        {
            name = "api-make-dirs",
            trigger = "OnDemand",
            conditions = new { users = new[] { "api-rule-user" } },
            actions = new[] { new { type = "CreateDirectory", options = new Dictionary<string, string> { ["Paths"] = "/reports" } } },
        }, Ct).ExpectAsync(HttpStatusCode.Created);
        var id = (await created.JsonAsync())["id"]!.GetValue<int>();

        var runs = await (await client.PostAsync($"/api/v1/event-rules/{id}/run", null, Ct).ExpectAsync(HttpStatusCode.OK)).ArrayAsync();
        Assert.Equal("Ok", Assert.Single(runs)!["status"]!.GetValue<string>());
        Assert.True(Directory.Exists(Path.Combine(_root.Path, "reports")));
        Assert.NotEmpty(await (await client.GetAsync($"/api/v1/event-rules/{id}/runs", Ct)).ArrayAsync());

        await client.PatchJsonAsync($"/api/v1/event-rules/{id}", new { enabled = false }).ExpectAsync(HttpStatusCode.OK);
        var rule = (await client.GetFromJsonAsync<JsonObject>($"/api/v1/event-rules/{id}", Ct))!;
        Assert.False(rule["enabled"]!.GetValue<bool>());
        Assert.Equal("CreateDirectory", rule["actions"]![0]!["type"]!.GetValue<string>());

        var invalid = await client.PostAsJsonAsync("/api/v1/event-rules", new { name = "bad", actions = new[] { new { type = "NoSuchAction" } } }, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);

        await client.DeleteAsync($"/api/v1/event-rules/{id}", Ct).ExpectAsync(HttpStatusCode.NoContent);

        await _factory.AddAdminAsync("no-events", AdminPermissions.ManageUsers);
        using var other = await _factory.ClientAsync("no-events");
        Assert.Equal(HttpStatusCode.Forbidden, (await other.GetAsync("/api/v1/event-rules", Ct)).StatusCode);
    }
}
