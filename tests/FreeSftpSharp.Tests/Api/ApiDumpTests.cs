using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Security;
using FreeSftpSharp.Tests.WebUi;

namespace FreeSftpSharp.Tests.Api;

/// <summary>
/// A dump of one server loaded into an empty one gives the same roles, administrators, virtual folders, users and
/// webhooks: password hashes and keys as they are, storage and webhook secrets encrypted again on the new server.
/// </summary>
[Collection(AdminUiCollection.Name)]
public sealed class ApiDumpTests : IDisposable
{
    private const string Passphrase = "correct horse battery staple";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly TempDirectory _root = new();

    public void Dispose() => _root.Dispose();

    [Fact]
    public async Task Dump_and_load_into_an_empty_server_give_the_same_objects()
    {
        await using var source = new ApiFactory();
        using var sourceClient = await source.SuperAdminAsync();
        var roleId = await source.AddRoleAsync("dump-tenant");
        await source.AddAdminAsync("dump-admin", AdminPermissions.ManageUsers, roleId);
        var sso = await source.AddAdminAsync("dump-sso", AdminPermissions.ViewAudit);
        sso.AuthenticationProvider = "oidc"; // #145
        Assert.True(await source.Admins.UpdateAdminAsync(sso, Ct));
        var folder = await (await sourceClient.PostAsJsonAsync("/api/v1/virtual-folders", new
        {
            name = "dump-folder",
            storage = new { provider = "s3", options = new Dictionary<string, object> { ["Bucket"] = "b", ["AccessKey"] = "AK", ["SecretKey"] = "s3-secret" } },
        }, Ct)).JsonAsync();
        var group = await (await sourceClient.PostAsJsonAsync("/api/v1/groups", new
        {
            name = "dump-group", permissions = new Dictionary<string, string[]> { ["/"] = ["List"] },
        }, Ct).ExpectAsync(HttpStatusCode.Created)).JsonAsync();
        await sourceClient.PostAsJsonAsync("/api/v1/event-rules", new
        {
            name = "dump-rule", trigger = "OnDemand",
            actions = new[] { new { type = "CreateDirectory", options = new Dictionary<string, string> { ["Paths"] = "/in" } } },
        }, Ct).ExpectAsync(HttpStatusCode.Created);
        var key = TestUserKeys.Ed25519();
        await sourceClient.PostAsJsonAsync("/api/v1/users", new
        {
            username = "dump-user",
            rootDirectory = _root.Path,
            password = "dump-password-1",
            publicKeys = key.AuthorizedKeysLine,
            permissions = new Dictionary<string, string[]> { ["/"] = ["List", "Download"] },
            virtualFolders = new[] { new { virtualFolderId = folder["id"]!.GetValue<int>(), mountPath = "/shared" } },
            roleId,
            secondaryGroupIds = new[] { group["id"]!.GetValue<int>() },
            maxSessions = 3,
        }, Ct).ExpectAsync(HttpStatusCode.Created);
        await sourceClient.PostAsJsonAsync("/api/v1/webhooks", new
        {
            name = "dump-hook", url = "http://127.0.0.1:9/hook", secret = "hook-secret-of-the-dump",
        }, Ct).ExpectAsync(HttpStatusCode.Created);

        var withoutSecrets = await (await sourceClient.GetAsync("/api/v1/dump", Ct)).JsonAsync();
        Assert.Contains("virtualFolders/dump-folder/SecretKey", withoutSecrets["omittedSecrets"]!.ToJsonString());
        Assert.DoesNotContain("s3-secret", withoutSecrets.ToJsonString());

        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/dump");
        request.Headers.Add("X-Dump-Passphrase", Passphrase);
        var dump = await (await sourceClient.SendAsync(request, Ct)).JsonAsync();
        Assert.DoesNotContain("s3-secret", dump.ToJsonString());
        Assert.DoesNotContain("hook-secret-of-the-dump", dump.ToJsonString());

        await using var target = new ApiFactory();
        using var targetClient = await target.SuperAdminAsync();

        var wrong = await LoadAsync(targetClient, dump, "not the passphrase");
        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);

        var loaded = await LoadAsync(targetClient, dump, Passphrase);
        Assert.Equal(HttpStatusCode.OK, loaded.StatusCode);
        var report = await loaded.JsonAsync();
        Assert.Empty(report["errors"]!.AsArray());

        var user = target.Repository.GetUser("dump-user");
        var original = source.Repository.GetUser("dump-user");
        Assert.Equal(original.HashedPassword, user.HashedPassword);
        Assert.True(PasswordHasher.Verify("dump-password-1", user.HashedPassword));
        Assert.Equal(key.Entry.KeyBase64, Assert.Single(user.PublicKeys!).KeyBase64);
        Assert.Equal(FilePermissions.List | FilePermissions.Download, user.Permissions!["/"]);
        var targetRole = Assert.Single(await target.Admins.ListRolesAsync(Ct), r => r.Name == "dump-tenant");
        Assert.Equal(targetRole.Id, user.RoleId);
        var targetFolder = Assert.Single(target.Repository.GetVirtualFolders(), f => f.Name == "dump-folder");
        Assert.Equal("/shared", Assert.Single(user.VirtualFolders).MountPath);
        Assert.Equal(targetFolder.Id, user.VirtualFolders[0].VirtualFolderId);
        var targetGroup = Assert.Single(target.Repository.GetGroups(), g => g.Name == "dump-group");
        Assert.Equal([targetGroup.Id], user.SecondaryGroupIds);
        Assert.Equal(3, user.MaxSessions);
        var rules = await (await targetClient.GetAsync("/api/v1/event-rules", Ct)).JsonAsync();
        Assert.Equal("dump-rule", Assert.Single(rules["items"]!.AsArray())!["name"]!.GetValue<string>());
        Assert.DoesNotContain("s3-secret", targetFolder.Storage.Options);
        var admin = (await target.Admins.GetAdminAsync("dump-admin", Ct))!;
        Assert.Equal((await source.Admins.GetAdminAsync("dump-admin", Ct))!.PasswordHash, admin.PasswordHash);
        Assert.Equal(targetRole.Id, admin.ScopeRoleId);
        Assert.Null(admin.AuthenticationProvider);
        Assert.Equal("oidc", (await target.Admins.GetAdminAsync("dump-sso", Ct))!.AuthenticationProvider);

        // The secret is encrypted again on the target: the API shows that it is stored.
        var view = (await targetClient.GetFromJsonAsync<JsonObject>($"/api/v1/virtual-folders/{targetFolder.Id}", Ct))!;
        Assert.Contains("SecretKey", view["storage"]!["storedSecrets"]!.ToJsonString());
        var hook = Assert.Single((await (await targetClient.GetAsync("/api/v1/webhooks", Ct)).JsonAsync())["items"]!.AsArray());
        Assert.True(hook!["hasSecret"]!.GetValue<bool>());

        // A second load in the default mode (add) reports the existing objects; skip leaves them.
        var again = await (await LoadAsync(targetClient, dump, Passphrase)).JsonAsync();
        Assert.NotEmpty(again["errors"]!.AsArray());
        var skipped = await (await LoadAsync(targetClient, dump, Passphrase, "skip")).JsonAsync();
        Assert.Empty(skipped["errors"]!.AsArray());
        Assert.Equal(0, skipped["added"]!.GetValue<int>());
    }

    [Fact]
    public async Task Only_a_super_admin_can_dump_or_load()
    {
        await using var factory = new ApiFactory();
        await factory.AddAdminAsync("dump-manager", AdminPermissions.ManageUsers | AdminPermissions.ManageAdmins | AdminPermissions.ManageSettings);
        using var client = await factory.ClientAsync("dump-manager");

        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/dump", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/api/v1/load", new { format = "freesftpsharp-dump", version = 1 }, Ct)).StatusCode);
    }

    private static Task<HttpResponseMessage> LoadAsync(HttpClient client, JsonObject dump, string passphrase, string? mode = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/load" + (mode == null ? "" : "?mode=" + mode))
        {
            Content = JsonContent.Create(dump),
        };
        request.Headers.Add("X-Dump-Passphrase", passphrase);
        return client.SendAsync(request, Ct);
    }
}
