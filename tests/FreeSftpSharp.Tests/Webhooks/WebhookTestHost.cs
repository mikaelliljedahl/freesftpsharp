using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.AspNetCore.DataProtection;
using FreeSftpSharp.Tests.Settings;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Webhooks;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.Webhooks;
using SshServer.Webhooks;
using SshServerModule.Events;

namespace FreeSftpSharp.Tests.Webhooks;

/// <summary>
/// The webhooks plug-in as a host builds it (AddSshServerEvents + AddWebhooks) on a SQLite settings database: a new
/// temporary file, or a given file to start a second host on the same database (a restart).
/// </summary>
public sealed class WebhookTestHost : IAsyncDisposable
{
    private readonly TempDirectory? _directory;
    private readonly ServiceProvider _provider;
    private bool _started;

    /// <param name="connectionString">A SQLite file; null: a new temporary file.</param>
    /// <param name="time">The clock; null: the system clock.</param>
    /// <param name="dataProtection">The keys of the secrets; give the same instance to a second host on the same database.</param>
    /// <param name="allowInsecure">Webhooks:AllowInsecureWebhooks (the receiver of the tests is http on loopback).</param>
    public WebhookTestHost(string? connectionString = null, TimeProvider? time = null, IDataProtectionProvider? dataProtection = null,
        Action<IServiceCollection>? configure = null, bool allowInsecure = true)
    {
        // A file, not one shared in-memory connection: the sink, the dispatcher and the test use the store at the same time.
        if (connectionString == null)
        {
            _directory = new TempDirectory();
            connectionString = _directory.SqliteConnectionString();
        }
        ConnectionString = connectionString;
        DataProtection = dataProtection ?? new EphemeralDataProtectionProvider();
        var options = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(connectionString).Options;
        // The repository creates and migrates the database, as at the start of the server.
        Repository = new SqlSettingsRepository(options, createHostKey: () => TestCredentials.HostKey);

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Webhooks:AllowInsecureWebhooks"] = allowInsecure ? "true" : "false" })
            .Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(time ?? TimeProvider.System);
        services.AddSingleton<IWebhookStore>(new SqlWebhookStore(options));
        services.AddSshServerEvents();
        services.AddWebhooks(configuration);
        services.Replace(ServiceDescriptor.Singleton(DataProtection));
        configure?.Invoke(services);
        _provider = services.BuildServiceProvider();
    }

    public SqlSettingsRepository Repository { get; }

    /// <summary>The database, for a second host on it.</summary>
    public string ConnectionString { get; }

    /// <summary>The keys of the secrets, for a second host on the same database.</summary>
    public IDataProtectionProvider DataProtection { get; }

    public IServiceProvider Services => _provider;

    public IWebhookStore Store => _provider.GetRequiredService<IWebhookStore>();

    public WebhookAdministrationService Admin => _provider.GetRequiredService<WebhookAdministrationService>();

    public WebhookSink Sink => _provider.GetServices<IEventSink>().OfType<WebhookSink>().Single();

    public WebhookEventHook Hook => _provider.GetServices<IEventHook>().OfType<WebhookEventHook>().Single();

    public IEventBus Bus => _provider.GetRequiredService<IEventBus>();

    public WebhookDispatcher Dispatcher => _provider.GetServices<IHostedService>().OfType<WebhookDispatcher>().Single();

    /// <summary>Starts the background sender.</summary>
    public async Task StartAsync()
    {
        await Dispatcher.StartAsync(CancellationToken.None);
        _started = true;
    }

    /// <summary>Stops the background sender, as at a stop of the server.</summary>
    public async Task StopAsync()
    {
        if (!_started)
            return;
        _started = false;
        await Dispatcher.StopAsync(CancellationToken.None);
    }

    /// <summary>Adds a webhook and fails the test when it is not valid.</summary>
    public async Task<int> AddWebhookAsync(WebhookInput input)
    {
        var result = await Admin.SaveAsync(input, CancellationToken.None);
        Assert.True(result.Succeeded, string.Join(" ", result.Errors));
        return result.Id!.Value;
    }

    /// <summary>Waits until the deliveries of a webhook match.</summary>
    public async Task<IReadOnlyList<WebhookDelivery>> WaitForDeliveriesAsync(int webhookId, Func<IReadOnlyList<WebhookDelivery>, bool> condition,
        TimeSpan? timeout = null, Action? onPoll = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(15));
        while (true)
        {
            var deliveries = await Store.ListDeliveriesAsync(webhookId, 100, CancellationToken.None);
            if (condition(deliveries))
                return deliveries;
            if (DateTime.UtcNow > deadline)
                throw new TimeoutException("The deliveries did not reach the expected state: " +
                    string.Join("; ", deliveries.Select(d => $"{d.EventType} {d.Status} attempts {d.Attempts} code {d.LastStatusCode} {d.LastError}")));
            onPoll?.Invoke();
            await Task.Delay(20);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        await _provider.DisposeAsync();
        Repository.Dispose();
        _directory?.Dispose();
    }
}
