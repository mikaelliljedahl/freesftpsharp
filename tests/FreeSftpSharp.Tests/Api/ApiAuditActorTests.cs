using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using FreeSftpSharp.Tests.WebUi;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.TwoFactor;
using SshServer.TwoFactor;

namespace FreeSftpSharp.Tests.Api;

/// <summary>
/// The changes of users, groups, virtual folders and server settings through the REST API have the administrator (and
/// its API key) as their actor in the audit log, and GET /api/v1/audit gives it (#134).
/// </summary>
[Collection(AdminUiCollection.Name)]
public sealed class ApiAuditActorTests : IClassFixture<ApiFactory>, IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private const AdminPermissions Provisioning = AdminPermissions.ManageUsers | AdminPermissions.ManageGroups
        | AdminPermissions.ManageFolders | AdminPermissions.ManageSettings | AdminPermissions.ViewAudit;

    private readonly ApiFactory _factory;
    private readonly TempDirectory _root = new();

    public ApiAuditActorTests(ApiFactory factory)
    {
        _factory = factory;
    }

    public void Dispose() => _root.Dispose();

    [Fact]
    public async Task Changes_with_a_token_have_the_administrator_as_actor()
    {
        await _factory.AddAdminAsync("provisioner", Provisioning);
        using var client = await _factory.ClientAsync("provisioner");

        await client.PostAsJsonAsync("/api/v1/users", new { username = "actor-user", rootDirectory = _root.Path }, Ct).ExpectAsync(HttpStatusCode.Created);
        await client.PostAsJsonAsync("/api/v1/groups", new { name = "actor-group" }, Ct).ExpectAsync(HttpStatusCode.Created);
        await client.PostAsJsonAsync("/api/v1/virtual-folders", new
        {
            name = "actor-folder", storage = new { provider = "local", options = new Dictionary<string, object> { ["RootDirectory"] = _root.Path } },
        }, Ct).ExpectAsync(HttpStatusCode.Created);
        await client.PatchJsonAsync("/api/v1/settings", new { serverBanner = "actor-banner" }).ExpectAsync(HttpStatusCode.OK);

        await WaitForActorAsync(client, "User/actor-user", "provisioner");
        await WaitForActorAsync(client, "Group/actor-group", "provisioner");
        await WaitForActorAsync(client, "VirtualFolder/actor-folder", "provisioner");
        await WaitForActorAsync(client, "ServerSettings/server", "provisioner");
    }

    [Fact]
    public async Task Changes_with_an_api_key_have_the_key_name_in_the_actor()
    {
        await _factory.AddAdminAsync("key-owner", Provisioning);
        using var owner = await _factory.ClientAsync("key-owner");
        using var client = _factory.ApiKeyClient(await ApiFactory.CreateApiKeyAsync(owner, "ci"));

        await client.PostAsJsonAsync("/api/v1/users", new { username = "actor-key-user", rootDirectory = _root.Path }, Ct).ExpectAsync(HttpStatusCode.Created);
        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync("/api/v1/users/actor-key-user", Ct)).StatusCode);

        var entries = await WaitForActorAsync(owner, "User/actor-key-user", "key-owner (API key ci)", count: 2);
        Assert.Equal(["Delete", "Add"], entries.Select(e => e!["type"]!.GetValue<string>()));
    }

    [Fact]
    public async Task App_password_and_second_factor_changes_with_an_api_key_have_the_key_name_in_the_actor()
    {
        await _factory.AddAdminAsync("secrets-owner", Provisioning);
        using var owner = await _factory.ClientAsync("secrets-owner");
        using var client = _factory.ApiKeyClient(await ApiFactory.CreateApiKeyAsync(owner, "helpdesk"));
        Assert.True(_factory.Repository.AddUser(new User { Username = "actor-secrets-user", UserRootDirectory = _root.Path }));
        var user = _factory.Repository.GetUser("actor-secrets-user");

        var created = await (await client.PostAsJsonAsync("/api/v1/users/actor-secrets-user/app-passwords", new { name = "Laptop" }, Ct)
            .ExpectAsync(HttpStatusCode.Created)).JsonAsync();
        var id = created["appPassword"]!["id"]!.GetValue<string>();
        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/api/v1/users/actor-secrets-user/app-passwords/{id}", Ct)).StatusCode);
        await TwoFactorTestKit.EnrolAsync(_factory.Services.GetRequiredService<TwoFactorService>(), TwoFactorSubject.ForUser(user),
            TimeProvider.System, "actor-secrets-user");
        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync("/api/v1/users/actor-secrets-user/two-factor", Ct)).StatusCode);

        // The first entry (Add) is made by the test itself, through the shared repository: the system.
        var entries = await WaitForActorAsync(owner, "User/actor-secrets-user", "secrets-owner (API key helpdesk)", count: 3, exceptSystem: true);
        Assert.Contains(entries, e => e!["message"]?.GetValue<string>()?.Contains("TwoFactor") == true);
    }

    /// <summary>The audit entries of the object from GET /api/v1/audit, once <paramref name="count"/> have the actor.</summary>
    private static async Task<List<JsonNode?>> WaitForActorAsync(HttpClient client, string path, string actor, int count = 1, bool exceptSystem = false)
    {
        // The audit sink writes in the background.
        for (var i = 0; i < 100; i++)
        {
            var page = await (await client.GetAsync("/api/v1/audit?limit=1000", Ct)).JsonAsync();
            var entries = page["items"]!.AsArray().Where(e => e!["path"]?.GetValue<string>() == path
                && !(exceptSystem && e["actor"]?.GetValue<string>() == "system")).ToList();
            if (entries.Count(e => e!["actor"]?.GetValue<string>() == actor) >= count)
            {
                Assert.All(entries, e => Assert.Equal(actor, e!["actor"]!.GetValue<string>()));
                return entries;
            }
            await Task.Delay(50, Ct);
        }
        Assert.Fail($"The audit log has no entry of {path} by {actor}.");
        return [];
    }
}
