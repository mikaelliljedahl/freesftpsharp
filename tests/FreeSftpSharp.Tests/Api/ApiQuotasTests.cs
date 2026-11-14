using System.Net;
using System.Net.Http.Json;
using FreeSftpSharp.Tests.Settings;
using FreeSftpSharp.Tests.WebUi;
using SshServer.Interfaces.Admins;

namespace FreeSftpSharp.Tests.Api;

/// <summary>The quotas and the bandwidth (#62) of users and groups through /api/v1.</summary>
[Collection(AdminUiCollection.Name)]
public sealed class ApiQuotasTests : IClassFixture<ApiFactory>, IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly ApiFactory _factory;
    private readonly TempDirectory _root = new();

    public ApiQuotasTests(ApiFactory factory)
    {
        _factory = factory;
    }

    public void Dispose() => _root.Dispose();

    [Fact]
    public async Task The_quotas_of_a_user_are_read_and_updated()
    {
        using var client = await _factory.SuperAdminAsync();
        await client.PostAsJsonAsync("/api/v1/users", new { username = "quota-user", rootDirectory = _root.Path }, Ct).ExpectAsync(HttpStatusCode.Created);

        var saved = await (await client.PutAsJsonAsync("/api/v1/users/quota-user/quotas", new
        {
            diskQuota = new { maxSizeBytes = 1_048_576, maxFiles = 10 },
            transferQuota = new { maxUploadBytes = 5_000_000 },
            bandwidth = new { uploadKiBPerSecond = 100, overrides = new[] { new { sources = new[] { "10.0.0.0/8" }, uploadKiBPerSecond = 0 } } },
        }, Ct).ExpectAsync(HttpStatusCode.OK)).JsonAsync();
        Assert.Equal(1_048_576, saved["diskQuota"]!["maxSizeBytes"]!.GetValue<long>());

        var user = _factory.Repository.GetUser("quota-user");
        Assert.Equal(10, user.DiskQuota!.MaxFiles);
        Assert.Equal(5_000_000, user.TransferQuota!.MaxUploadBytes);
        Assert.Equal(["10.0.0.0/8"], user.Bandwidth!.Overrides![0].Sources);

        var quotas = await (await client.GetAsync("/api/v1/users/quota-user/quotas", Ct).ExpectAsync(HttpStatusCode.OK)).JsonAsync();
        Assert.Equal(10, quotas["settings"]!["diskQuota"]!["maxFiles"]!.GetValue<long>());
        Assert.Single(quotas["usage"]!["disk"]!.AsArray());
        Assert.NotNull(quotas["usage"]!["transfer"]);

        await client.PostAsync("/api/v1/users/quota-user/quotas/scan", null, Ct).ExpectAsync(HttpStatusCode.Accepted);
        await client.PostAsync("/api/v1/users/quota-user/quotas/transfer/reset", null, Ct).ExpectAsync(HttpStatusCode.NoContent);

        // A patch of the user keeps the quotas; a quota of 0 everywhere is not set.
        await client.PatchJsonAsync("/api/v1/users/quota-user", new { description = "quota test" }).ExpectAsync(HttpStatusCode.OK);
        Assert.NotNull(_factory.Repository.GetUser("quota-user").DiskQuota);
        await client.PutAsJsonAsync("/api/v1/users/quota-user/quotas", new { diskQuota = new { maxSizeBytes = 0 } }, Ct).ExpectAsync(HttpStatusCode.OK);
        Assert.Null(_factory.Repository.GetUser("quota-user").DiskQuota);
        Assert.Null(_factory.Repository.GetUser("quota-user").TransferQuota);

        var invalid = await client.PutAsJsonAsync("/api/v1/users/quota-user/quotas", new
        {
            diskQuota = new { maxSizeBytes = -1 },
            bandwidth = new { overrides = new[] { new { sources = new[] { "not-a-network" } } } },
        }, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        var errors = (await invalid.JsonAsync())["errors"]!.AsObject();
        Assert.True(errors.ContainsKey("diskQuota"));
        Assert.True(errors.ContainsKey("bandwidth"));
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/v1/users/no-such-user/quotas", Ct)).StatusCode);
    }

    [Fact]
    public async Task The_quotas_of_a_group_are_read_and_updated_with_ManageGroups()
    {
        using var client = await _factory.SuperAdminAsync();
        var id = (await (await client.PostAsJsonAsync("/api/v1/groups", new { name = "quota-group" }, Ct).ExpectAsync(HttpStatusCode.Created))
            .JsonAsync())["id"]!.GetValue<int>();

        await client.PutAsJsonAsync($"/api/v1/groups/{id}/quotas", new { transferQuota = new { maxTotalBytes = 1_000 } }, Ct)
            .ExpectAsync(HttpStatusCode.OK);
        Assert.Equal(1_000, _factory.Repository.GetGroup(id)!.TransferQuota!.MaxTotalBytes);
        var view = await (await client.GetAsync($"/api/v1/groups/{id}/quotas", Ct).ExpectAsync(HttpStatusCode.OK)).JsonAsync();
        Assert.Equal(1_000, view["transferQuota"]!["maxTotalBytes"]!.GetValue<long>());

        await _factory.AddAdminAsync("quota-reader", AdminPermissions.ManageUsers);
        using var reader = await _factory.ClientAsync("quota-reader");
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync($"/api/v1/groups/{id}/quotas", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.PutAsJsonAsync($"/api/v1/groups/{id}/quotas", new { }, Ct)).StatusCode);
    }
}
