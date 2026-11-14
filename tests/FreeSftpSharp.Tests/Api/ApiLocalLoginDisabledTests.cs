using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using FreeSftpSharp.Tests.WebUi;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Api.ApiKeys;
using SshServer.Interfaces.Admins;

namespace FreeSftpSharp.Tests.Api;

/// <summary>The REST API with the password login of the administrators off (<c>Auth:Oidc:Admin:DisableLocalLogin</c>, #73).</summary>
public sealed class ApiLocalLoginDisabledFactory : ApiFactory
{
    protected override void ConfigureSettings(IWebHostBuilder builder)
    {
        builder.UseSetting("Auth:Oidc:Admin:Authority", "https://idp.test");
        builder.UseSetting("Auth:Oidc:Admin:ClientId", "freesftpsharp-admin");
        builder.UseSetting("Auth:Oidc:Admin:DisableLocalLogin", "true");
    }
}

[Collection(AdminUiCollection.Name)]
public sealed class ApiLocalLoginDisabledTests : IClassFixture<ApiLocalLoginDisabledFactory>
{
    private readonly ApiLocalLoginDisabledFactory _factory;

    public ApiLocalLoginDisabledTests(ApiLocalLoginDisabledFactory factory)
    {
        _factory = factory;
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task The_password_token_endpoint_refuses_also_the_right_password()
    {
        using var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/token",
            new { username = AdminUiFactory.AdminUserName, password = AdminUiFactory.AdminPassword }, ApiFactory.Json, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var problem = await response.Content.ReadFromJsonAsync<JsonObject>(ApiFactory.Json, Ct);
        Assert.Contains("DisableLocalLogin", problem!["detail"]!.GetValue<string>());
        Assert.DoesNotContain("accessToken", await response.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task An_API_key_keeps_working()
    {
        var admin = await _factory.Admins.GetAdminAsync(AdminUiFactory.AdminUserName, Ct);
        var keys = _factory.Services.GetRequiredService<ApiKeyService>();
        var created = await keys.CreateAsync(new AdminActor(admin!.Username, AdminPermissionRules.Everything, null), "automation", null, null, Ct);
        using var client = _factory.ApiKeyClient(created.Key);

        var status = await client.GetAsync("/api/v1/status", Ct);

        Assert.Equal(HttpStatusCode.OK, status.StatusCode);
    }
}
