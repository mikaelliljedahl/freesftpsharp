using System.Net;
using FreeSftpSharp.Tests.Settings;
using FreeSftpSharp.Tests.WebUi;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Shares;

namespace FreeSftpSharp.Tests.Api;

/// <summary>/api/v1/shares (#70) over the SQL share store: the list without the password hash, the scope, the revoke.</summary>
[Collection(AdminUiCollection.Name)]
public sealed class ApiSharesTests : IClassFixture<ApiFactory>, IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly ApiFactory _factory;
    private readonly TempDirectory _root = new();

    public ApiSharesTests(ApiFactory factory)
    {
        _factory = factory;
    }

    public void Dispose() => _root.Dispose();

    private IShareStore Store => _factory.Services.GetRequiredService<IShareStore>();

    private async Task<Share> AddShareAsync(string username, int? roleId = null, int maxUses = 0)
    {
        if (_factory.Repository.GetUser(username) == null)
            Assert.True(_factory.Repository.AddUser(new User { Username = username, UserRootDirectory = _root.Path, RoleId = roleId }));
        var user = _factory.Repository.GetUser(username);
        var share = new Share
        {
            Id = ShareId.New(),
            UserId = user.Id,
            Username = username,
            Name = "Share " + username,
            Paths = ["/out"],
            Scope = ShareScope.Read,
            PasswordHash = PasswordHasher.Hash("Secret-Share-1", PasswordHasher.MinimumIterations),
            MaxUses = maxUses,
            CreatedAt = DateTime.UtcNow,
        };
        await Store.AddAsync(share, Ct);
        return share;
    }

    [Fact]
    public async Task Administrators_list_and_revoke_shares_without_seeing_the_password_hash()
    {
        var share = await AddShareAsync("api-share-owner");
        using var client = await _factory.SuperAdminAsync();

        var list = await client.GetAsync("/api/v1/shares?username=api-share-owner", Ct);
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        var text = await list.Content.ReadAsStringAsync(Ct);
        Assert.DoesNotContain("PBKDF2", text);
        var item = Assert.Single((await list.JsonAsync())["items"]!.AsArray());
        Assert.Equal(share.Id, item!["id"]!.GetValue<string>());
        Assert.True(item["hasPassword"]!.GetValue<bool>());
        Assert.Equal("Read", item["scope"]!.GetValue<string>());

        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/api/v1/shares/{share.Id}", Ct)).StatusCode);
        Assert.Null(await Store.GetAsync(share.Id, Ct));
        Assert.Equal(HttpStatusCode.NotFound, (await client.DeleteAsync($"/api/v1/shares/{share.Id}", Ct)).StatusCode);
    }

    [Fact]
    public async Task A_scoped_administrator_sees_only_the_shares_of_its_users_and_ManageUsers_is_needed()
    {
        var roleA = await _factory.AddRoleAsync("share-tenant-a");
        var roleB = await _factory.AddRoleAsync("share-tenant-b");
        var mine = await AddShareAsync("share-scope-a", roleA);
        var theirs = await AddShareAsync("share-scope-b", roleB);
        await _factory.AddAdminAsync("share-admin-a", AdminPermissions.ManageUsers, roleA);
        await _factory.AddAdminAsync("share-viewer", AdminPermissions.ViewConnections);
        using var scoped = await _factory.ClientAsync("share-admin-a");
        using var viewer = await _factory.ClientAsync("share-viewer");

        var items = (await (await scoped.GetAsync("/api/v1/shares", Ct)).JsonAsync())["items"]!.AsArray().Select(i => i!["id"]!.GetValue<string>()).ToList();
        Assert.Contains(mine.Id, items);
        Assert.DoesNotContain(theirs.Id, items);
        Assert.Equal(HttpStatusCode.NotFound, (await scoped.DeleteAsync($"/api/v1/shares/{theirs.Id}", Ct)).StatusCode);
        Assert.NotNull(await Store.GetAsync(theirs.Id, Ct));
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync("/api/v1/shares", Ct)).StatusCode);
    }

    [Fact]
    public async Task The_SQL_store_counts_uses_up_to_the_limit_and_removes_the_shares_of_a_removed_user()
    {
        var share = await AddShareAsync("share-sql-owner", maxUses: 2);

        Assert.True(await Store.TryUseAsync(share.Id, DateTime.UtcNow, Ct));
        Assert.True(await Store.TryUseAsync(share.Id, DateTime.UtcNow, Ct));
        Assert.False(await Store.TryUseAsync(share.Id, DateTime.UtcNow, Ct));
        var stored = await Store.GetAsync(share.Id, Ct);
        Assert.Equal(2, stored!.UsedCount);
        Assert.NotNull(stored.LastUsedAt);
        Assert.Equal(["/out"], stored.Paths);

        Assert.True(_factory.Repository.RemoveUser("share-sql-owner"));
        Assert.Null(await Store.GetAsync(share.Id, Ct));
    }
}
