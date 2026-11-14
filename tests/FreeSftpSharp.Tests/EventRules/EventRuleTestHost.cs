using System.Collections.Concurrent;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using FreeSftpSharp.Tests.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SshServer.EventRules;
using SshServer.EventRules.Actions;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Storage;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.EventRules;
using SshServerModule.Events;

namespace FreeSftpSharp.Tests.EventRules;

/// <summary>
/// The event rules plug-in as a host builds it (AddSshServerEvents + AddEventRules) on a SQLite settings database, with
/// in-memory storage per user (<see cref="InMemoryFileSystemFactory"/>), a fake mail server and a fake process runner.
/// Give the connection string of another host for a second node on the same database.
/// </summary>
public sealed class EventRuleTestHost : IAsyncDisposable
{
    private readonly TempDirectory? _directory;
    private readonly ServiceProvider _provider;
    private readonly List<IHostedService> _started = new();

    public EventRuleTestHost(TimeProvider? time = null, IReadOnlyDictionary<string, string?>? settings = null,
        Action<IServiceCollection>? configure = null, string? connectionString = null, IFileSystemFactory? files = null)
    {
        if (connectionString == null)
        {
            _directory = new TempDirectory();
            connectionString = _directory.SqliteConnectionString();
        }
        ConnectionString = connectionString;
        var options = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(connectionString).Options;
        Repository = new SqlSettingsRepository(options, createHostKey: () => TestCredentials.HostKey);
        Files = files as InMemoryFileSystemFactory ?? new InMemoryFileSystemFactory(time);

        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings ?? new Dictionary<string, string?>()).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(time ?? TimeProvider.System);
        services.AddSingleton<IEventRuleStore>(new SqlEventRuleStore(options));
        services.AddSingleton<ISettingsRepository>(Repository);
        services.AddSingleton<IFileSystemFactory>(files ?? Files);
        services.AddSshServerEvents();
        services.AddEventRules(configuration);
        services.Replace(ServiceDescriptor.Singleton<IEmailSender>(Emails));
        services.Replace(ServiceDescriptor.Singleton<ICommandRunner>(Commands));
        configure?.Invoke(services);
        _provider = services.BuildServiceProvider();
    }

    public string ConnectionString { get; }

    public SqlSettingsRepository Repository { get; }

    public InMemoryFileSystemFactory Files { get; }

    public FakeEmailSender Emails { get; } = new();

    public FakeCommandRunner Commands { get; } = new();

    public IServiceProvider Services => _provider;

    public IEventRuleStore Store => _provider.GetRequiredService<IEventRuleStore>();

    public EventRuleAdministrationService Admin => _provider.GetRequiredService<EventRuleAdministrationService>();

    public EventRuleRunner Runner => _provider.GetRequiredService<EventRuleRunner>();

    public EventRuleCatalog Catalog => _provider.GetRequiredService<EventRuleCatalog>();

    public IEventBus Bus => _provider.GetRequiredService<IEventBus>();

    public EventRuleHook Hook => _provider.GetServices<IEventHook>().OfType<EventRuleHook>().Single();

    public EventRuleScheduler Scheduler => _provider.GetServices<IHostedService>().OfType<EventRuleScheduler>().Single();

    public EventRuleWorker Worker => _provider.GetServices<IHostedService>().OfType<EventRuleWorker>().Single();

    /// <summary>Starts the worker (the runs of events) and, when asked, the scheduler loop.</summary>
    public async Task StartAsync(bool scheduler = false)
    {
        await StartAsync(Worker);
        if (scheduler)
            await StartAsync(Scheduler);
    }

    private async Task StartAsync(IHostedService service)
    {
        await service.StartAsync(CancellationToken.None);
        _started.Add(service);
    }

    public User AddUser(string username)
    {
        var user = new User { Username = username, UserRootDirectory = "/unused", HashedPassword = TestCredentials.HashPassword("pw") };
        Assert.True(Repository.AddUser(user));
        return Repository.GetUser(username);
    }

    /// <summary>Adds a rule and fails the test when it is not valid.</summary>
    public async Task<int> AddRuleAsync(EventRuleInput input)
    {
        var result = await Admin.SaveAsync(AdminActor.System, input, CancellationToken.None);
        Assert.True(result.Succeeded, string.Join(" ", result.Errors));
        return result.Id!.Value;
    }

    /// <summary>Waits until the runs of a rule match.</summary>
    public async Task<IReadOnlyList<EventRuleRun>> WaitForRunsAsync(int ruleId, Func<IReadOnlyList<EventRuleRun>, bool> condition,
        Action? onPoll = null, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(15));
        while (true)
        {
            var runs = await Store.ListRunsAsync(ruleId, 100, CancellationToken.None);
            if (condition(runs))
                return runs;
            if (DateTime.UtcNow > deadline)
                throw new TimeoutException("The runs did not reach the expected state: " + string.Join(" | ", runs.Select(r => $"{r.Status} {r.Message}")));
            onPoll?.Invoke();
            await Task.Delay(20);
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var service in _started)
            await service.StopAsync(CancellationToken.None);
        await _provider.DisposeAsync();
        Repository.Dispose();
        _directory?.Dispose();
    }

    /// <summary>One upload event of a user.</summary>
    public static FileEvent Upload(string username, string path, long size = 10, string protocol = "SFTP") => new(FileEventType.Upload)
    {
        Timestamp = DateTimeOffset.UtcNow,
        Username = username,
        VirtualPath = path,
        FileSize = size,
        Protocol = protocol,
        RemoteIp = "192.0.2.10",
    };
}

/// <summary>One <see cref="InMemoryFileSystem"/> per user; keeps the client context of each call.</summary>
public sealed class InMemoryFileSystemFactory : IFileSystemFactory
{
    private readonly ConcurrentDictionary<string, InMemoryFileSystem> _systems = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<ClientContext> _clients = new();
    private readonly TimeProvider? _time;

    public InMemoryFileSystemFactory(TimeProvider? time = null)
    {
        _time = time;
    }

    public IReadOnlyList<ClientContext> Clients => _clients.ToArray();

    public InMemoryFileSystem For(string username) => _systems.GetOrAdd(username, _ => new InMemoryFileSystem(time: _time));

    public ValueTask<IFileSystem> CreateAsync(User user, ClientContext client, CancellationToken ct)
    {
        _clients.Enqueue(client);
        return ValueTask.FromResult<IFileSystem>(For(user.Username));
    }
}

/// <summary>An <see cref="IEmailSender"/> that keeps the messages.</summary>
public sealed class FakeEmailSender : IEmailSender
{
    private readonly ConcurrentQueue<EmailMessage> _sent = new();

    public bool IsConfigured { get; set; } = true;

    public Exception? Failure { get; set; }

    public IReadOnlyList<EmailMessage> Sent => _sent.ToArray();

    public Task SendAsync(EmailMessage message, CancellationToken ct)
    {
        if (Failure != null)
            throw Failure;
        _sent.Enqueue(message);
        return Task.CompletedTask;
    }
}

/// <summary>An <see cref="ICommandRunner"/> that keeps the requests and answers with <see cref="Result"/>.</summary>
public sealed class FakeCommandRunner : ICommandRunner
{
    private readonly ConcurrentQueue<CommandRequest> _requests = new();

    public Func<CommandRequest, CommandResult> Result { get; set; } = _ => new CommandResult(0, false, "done");

    public IReadOnlyList<CommandRequest> Requests => _requests.ToArray();

    public Task<CommandResult> RunAsync(CommandRequest request, CancellationToken ct)
    {
        _requests.Enqueue(request);
        return Task.FromResult(Result(request));
    }
}

/// <summary>File helpers over <see cref="InMemoryFileSystem"/>.</summary>
public static class MemoryFiles
{
    public static async Task WriteAsync(IFileSystem fileSystem, string path, string content, DateTime? lastWriteUtc = null)
    {
        await FileOperations.EnsureDirectoryAsync(fileSystem, VirtualPath.GetParent(VirtualPath.Normalize(path)), CancellationToken.None);
        await using (var handle = await fileSystem.OpenAsync(path, FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate, null, CancellationToken.None))
            await handle.WriteAsync(0, System.Text.Encoding.UTF8.GetBytes(content), CancellationToken.None);
        if (lastWriteUtc is { } time)
            await fileSystem.SetAttributesAsync(path, new FileAttributesUpdate { LastWriteTimeUtc = time, LastAccessTimeUtc = time }, CancellationToken.None);
    }

    public static async Task<string?> ReadAsync(IFileSystem fileSystem, string path)
    {
        if (await fileSystem.StatAsync(path, true, CancellationToken.None) == null)
            return null;
        var bytes = await FileOperations.ReadAllAsync(fileSystem, path, long.MaxValue, CancellationToken.None);
        return System.Text.Encoding.UTF8.GetString(bytes!);
    }

    public static async Task<bool> ExistsAsync(IFileSystem fileSystem, string path) => await fileSystem.StatAsync(path, true, CancellationToken.None) != null;
}
