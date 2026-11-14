using System.Net;
using System.Net.Http.Headers;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.WebUi;
using FxSsh.SshServerModule;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Observability;
using SshServerModule.Observability;

namespace FreeSftpSharp.Tests.Observability;

/// <summary>The admin UI host with the <c>Observability</c> section set by a test.</summary>
public class ObservabilityFactory : AdminUiFactory
{
    public const string ApiKey = "scrape-key-1234";

    protected virtual IReadOnlyDictionary<string, string> Settings => new Dictionary<string, string>
    {
        ["Observability:Health:Enabled"] = "true",
        ["Observability:Prometheus:Enabled"] = "true",
        ["Observability:Prometheus:ApiKey"] = ApiKey,
    };

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        foreach (var (key, value) in Settings)
            builder.UseSetting(key, value);
    }
}

/// <summary>A readiness check that fails, like a database that cannot be read.</summary>
public sealed class FailingDatabaseFactory : ObservabilityFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(services => services.RemoveAll<ISettingsRepository>()
            .AddSingleton<ISettingsRepository>(new ThrowingSettingsRepository()));
    }

    private sealed class ThrowingSettingsRepository : ISettingsRepository
    {
        public ServerSettings ServerSettings => throw new IOException("config.db is unreadable");
        public bool UpdateServerSettings(ServerSettings updatedSettings) => false;
        public User GetUser(string username) => null!;
        public bool RemoveUser(string username) => false;
        public List<User> GetAllUsers() => throw new IOException("config.db is unreadable");
        public bool AddUser(User newUser) => false;
        public bool UpdateUser(User updatedUser) => false;
        public List<SshServer.Interfaces.Storage.VirtualFolder> GetVirtualFolders() => throw new IOException("config.db is unreadable");
        public SshServer.Interfaces.Storage.VirtualFolder? GetVirtualFolder(int id) => null;
        public bool AddVirtualFolder(SshServer.Interfaces.Storage.VirtualFolder folder) => false;
        public bool UpdateVirtualFolder(SshServer.Interfaces.Storage.VirtualFolder folder) => false;
        public bool RemoveVirtualFolder(int id) => false;
        public void Dispose() { }
    }
}

// In the admin UI collection like every test that starts the web host: Program builds its Serilog logger from the
// process-wide configuration, and NormalStartLoggingTests adds an in-memory sink through environment variables while
// it runs. A host built in parallel (here the one with the failing database check) also got that sink, and its
// expected "Unhealthy" error showed up in that test's log (seen on Windows CI).
[Collection(AdminUiCollection.Name)]
public sealed class ObservabilityEndpointTests : IClassFixture<ObservabilityFactory>, IClassFixture<FailingDatabaseFactory>, IClassFixture<AdminUiFactory>
{
    private readonly ObservabilityFactory _on;
    private readonly FailingDatabaseFactory _failing;
    private readonly AdminUiFactory _default;

    public ObservabilityEndpointTests(ObservabilityFactory on, FailingDatabaseFactory failing, AdminUiFactory defaults)
    {
        _on = on;
        _failing = failing;
        _default = defaults;
    }

    private static HttpClient Anonymous(WebApplicationFactory<Program> factory)
        => factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    [Theory]
    [InlineData("/healthz")]
    [InlineData("/readyz")]
    [InlineData("/metrics")]
    public async Task By_default_the_host_has_no_health_or_metrics_endpoint(string path)
    {
        var response = await Anonymous(_default).GetAsync(path, TestContext.Current.CancellationToken);

        // The admin login catches the request (a redirect to the login); nothing answers 200.
        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains("WWW-Authenticate"));
        Assert.Null(_default.Services.GetService<HealthCheckService>());
        Assert.False(ObservabilityOptions.From(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()).Health.Enabled);
        Assert.False(ObservabilityOptions.From(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()).Prometheus.Enabled);
        Assert.True(string.IsNullOrEmpty(ObservabilityOptions.From(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()).Otlp.Endpoint));
    }

    [Fact]
    public async Task Healthz_and_readyz_answer_200_without_a_login()
    {
        var client = Anonymous(_on);

        var live = await client.GetAsync("/healthz", TestContext.Current.CancellationToken);
        var ready = await client.GetAsync("/readyz", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        Assert.Equal("Healthy", await ready.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Readyz_answers_503_when_the_database_is_not_readable_but_healthz_stays_200()
    {
        var client = Anonymous(_failing);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/healthz", TestContext.Current.CancellationToken)).StatusCode);
        var ready = await client.GetAsync("/readyz", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
        Assert.Equal("Unhealthy", await ready.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task The_json_detail_of_readyz_is_only_for_the_operator()
    {
        var client = Anonymous(_failing);

        var plain = await client.GetAsync("/readyz?detail=true", TestContext.Current.CancellationToken);
        Assert.Equal("Unhealthy", await plain.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        var request = new HttpRequestMessage(HttpMethod.Get, "/readyz?detail=true");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ObservabilityFactory.ApiKey);
        var detail = await client.SendAsync(request, TestContext.Current.CancellationToken);
        var body = await detail.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, detail.StatusCode);
        Assert.Contains("\"database\"", body);
        Assert.Contains("not readable", body);
    }

    [Fact]
    public async Task Metrics_needs_the_key_and_then_shows_the_instruments()
    {
        var registry = _on.Services.GetRequiredService<IConnectionRegistry>();
        registry.Register(new ConnectionRegistration(ConnectionProtocols.Sftp, "127.0.0.1:5", _ => Task.CompletedTask));
        var client = Anonymous(_on);

        var denied = await client.GetAsync("/metrics", TestContext.Current.CancellationToken);
        var wrong = new HttpRequestMessage(HttpMethod.Get, "/metrics");
        wrong.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "not-the-key");
        var wrongResponse = await client.SendAsync(wrong, TestContext.Current.CancellationToken);
        var request = new HttpRequestMessage(HttpMethod.Get, "/metrics");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ObservabilityFactory.ApiKey);
        var ok = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        var text = await ok.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("freesftpsharp_connections", text);
    }

    [Fact]
    public async Task The_listener_check_is_not_ready_before_the_ssh_server_started()
    {
        var server = new HostedServer(NullLogger<HostedServer>.Instance, null!, new InMemorySettingsRepository(new ServerSettings()));
        var check = new ListenerHealthCheck([server]);

        var result = await check.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal(HealthStatus.Healthy, (await new ListenerHealthCheck([]).CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken)).Status);
    }
}
