using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using FreeSftpSharp.Tests.WebUi;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Api;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Api;
using SshServer.Interfaces.Audit;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Webhooks;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.Admins;
using SshServer.Settings.Sql.Api;
using SshServer.Settings.Sql.Audit;
using SshServer.Settings.Sql.Webhooks;

namespace FreeSftpSharp.Tests.Api;

/// <summary>
/// The admin host with the REST API on (<c>Api:Enabled</c>) and every store in a SQLite file of its own (users, admins,
/// API keys, audit log, webhooks), so the API runs over the same stores as in production. The configured super admin
/// (<see cref="AdminUiFactory.AdminUserName"/>) is imported at the start.
/// </summary>
public sealed class ApiFactory : AdminUiFactory
{
    public const string Password = "Api-Test-Password-1";

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    private static readonly string PasswordHash = PasswordHasher.Hash(Password, PasswordHasher.MinimumIterations);

    private readonly TempDirectory _directory = new();
    private readonly DbContextOptions<SettingsDbContext> _db;

    public ApiFactory()
    {
        _db = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(_directory.SqliteConnectionString()).Options;
        // The repository creates and migrates the database, as at the start of the server.
        _ = new SqlSettingsRepository(_db, createHostKey: () => TestCredentials.HostKey);
    }

    public string DataDirectory => _directory.Path;

    public ISettingsRepository Repository => Services.GetRequiredService<ISettingsRepository>();

    public IAdminStore Admins => Services.GetRequiredService<IAdminStore>();

    public IApiKeyStore ApiKeys => Services.GetRequiredService<IApiKeyStore>();

    public IAuditLog Audit => Services.GetRequiredService<IAuditLog>();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("Api:Enabled", "true");
        builder.UseSetting("Api:TokenRequestsPerMinute", "10000");
        builder.UseSetting("Webhooks:AllowInsecureWebhooks", "true");
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<ISettingsRepository>();
            services.AddSingleton<ISettingsRepository>(sp => new SqlSettingsRepository(_db, events: sp.GetService<IEventBus>(), actors: sp.GetRequiredService<AuditActorContext>(),
                createHostKey: () => TestCredentials.HostKey));
            services.RemoveAll<IAdminStore>();
            services.AddSingleton<IAdminStore>(new SqlAdminStore(_db));
            services.RemoveAll<IAuditLog>();
            services.AddSingleton<IAuditLog>(new SqlAuditLog(_db));
            services.RemoveAll<IWebhookStore>();
            services.AddSingleton<IWebhookStore>(new SqlWebhookStore(_db));
            services.RemoveAll<SshServer.Interfaces.EventRules.IEventRuleStore>();
            services.AddSingleton<SshServer.Interfaces.EventRules.IEventRuleStore>(new SshServer.Settings.Sql.EventRules.SqlEventRuleStore(_db));
            services.RemoveAll<SshServer.Interfaces.Quotas.IQuotaUsageStore>();
            services.AddSingleton<SshServer.Interfaces.Quotas.IQuotaUsageStore>(new SshServer.Settings.Sql.Quotas.SqlQuotaUsageStore(_db));
            services.RemoveAll<SqlApiKeyStore>();
            services.AddSingleton(new SqlApiKeyStore(_db));
        });
    }

    /// <summary>Adds an administrator with <see cref="Password"/>.</summary>
    public async Task<Admin> AddAdminAsync(string username, AdminPermissions permissions, int? scopeRoleId = null)
    {
        var admin = new Admin { Username = username, PasswordHash = PasswordHash, Permissions = permissions, ScopeRoleId = scopeRoleId };
        Assert.True(await Admins.AddAdminAsync(admin, CancellationToken.None));
        return admin;
    }

    public async Task<int> AddRoleAsync(string name)
    {
        var role = new Role { Name = name };
        Assert.True(await Admins.AddRoleAsync(role, CancellationToken.None));
        return role.Id;
    }

    /// <summary>A bearer token from POST /api/v1/token.</summary>
    public async Task<string> TokenAsync(string username, string password)
    {
        using var client = CreateClient();
        var response = await client.PostAsJsonAsync("/api/v1/token", new { username, password }, Json, TestContext.Current.CancellationToken);
        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>(Json, TestContext.Current.CancellationToken);
        return body!["accessToken"]!.GetValue<string>();
    }

    public HttpClient BearerClient(string token)
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    /// <summary>A client of the configured super admin.</summary>
    public async Task<HttpClient> SuperAdminAsync() => BearerClient(await TokenAsync(AdminUserName, AdminPassword));

    public async Task<HttpClient> ClientAsync(string username) => BearerClient(await TokenAsync(username, Password));

    public HttpClient ApiKeyClient(string key)
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Add("X-API-Key", key);
        return client;
    }

    /// <summary>Creates an API key with the bearer client and returns the key.</summary>
    public static async Task<string> CreateApiKeyAsync(HttpClient client, string name, params string[] scopes)
    {
        var response = await client.PostAsJsonAsync("/api/v1/api-keys", new { name, scopes = scopes.Length == 0 ? null : scopes }, Json,
            TestContext.Current.CancellationToken);
        Assert.Equal(System.Net.HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>(Json, TestContext.Current.CancellationToken);
        return body!["key"]!.GetValue<string>();
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
            _directory.Dispose();
    }
}

internal static class ApiResponses
{
    public static async Task<JsonObject> JsonAsync(this HttpResponseMessage response) =>
        (await response.Content.ReadFromJsonAsync<JsonObject>(ApiFactory.Json, TestContext.Current.CancellationToken))!;

    public static async Task<JsonArray> ArrayAsync(this HttpResponseMessage response) =>
        (await response.Content.ReadFromJsonAsync<JsonArray>(ApiFactory.Json, TestContext.Current.CancellationToken))!;

    /// <summary>Asserts the status code, with the body in the message when it differs.</summary>
    public static async Task<HttpResponseMessage> ExpectAsync(this Task<HttpResponseMessage> request, System.Net.HttpStatusCode expected)
    {
        var response = await request;
        if (response.StatusCode != expected)
            Assert.Fail($"Expected {expected}, got {response.StatusCode}: {await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)}");
        return response;
    }

    public static Task<HttpResponseMessage> PatchJsonAsync(this HttpClient client, string url, object patch) =>
        client.PatchAsync(url, new StringContent(JsonSerializer.Serialize(patch, ApiFactory.Json), System.Text.Encoding.UTF8, "application/merge-patch+json"),
            TestContext.Current.CancellationToken);
}
