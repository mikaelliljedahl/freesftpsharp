using System.Net;
using System.Net.Http.Headers;
using System.Text;
using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Storage;
using FreeSftpSharp.WebDav;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.TwoFactor;
using SshServerModule.Connections;

namespace FreeSftpSharp.Tests.WebDav;

/// <summary>
/// The "memory" storage provider of the WebDAV tests: every store name is one <see cref="InMemoryFileSystem"/>, kept by
/// the provider, so a test can look into the storage of a user.
/// </summary>
public sealed class InMemoryStorageProvider(StorageCapabilities capabilities) : StorageProvider<InMemoryStorageOptions>
{
    private readonly Dictionary<string, InMemoryFileSystem> _stores = new(StringComparer.Ordinal);

    public override string Name => "memory";

    /// <summary>When set, every open of a file fails with <see cref="FileSystemError.Failure"/> (a broken storage).</summary>
    public bool FailOpens { get; set; }

    public InMemoryFileSystem Store(string name)
    {
        lock (_stores)
        {
            if (!_stores.TryGetValue(name, out var store))
                _stores[name] = store = new InMemoryFileSystem(capabilities);
            return store;
        }
    }

    protected override IReadOnlyList<string> ValidateOptions(InMemoryStorageOptions options) => [];

    protected override ValueTask<IFileSystem> CreateFileSystemAsync(InMemoryStorageOptions options, CancellationToken ct) =>
        ValueTask.FromResult<IFileSystem>(FailOpens ? new FailingOpenFileSystem(Store(options.Store)) : Store(options.Store));

    private sealed class FailingOpenFileSystem(IFileSystem inner) : IFileSystem
    {
        public StorageCapabilities Capabilities => inner.Capabilities;
        public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct) => inner.StatAsync(path, followLinks, ct);
        public IAsyncEnumerable<FileSystemEntry> ListAsync(string path, CancellationToken ct) => inner.ListAsync(path, ct);
        public ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct) =>
            throw new FileSystemException(FileSystemError.Failure, "The storage is broken.");
        public ValueTask CreateDirectoryAsync(string path, CancellationToken ct) => inner.CreateDirectoryAsync(path, ct);
        public ValueTask DeleteFileAsync(string path, CancellationToken ct) => inner.DeleteFileAsync(path, ct);
        public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct) => inner.DeleteDirectoryAsync(path, ct);
        public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct) => inner.RenameAsync(oldPath, newPath, flags, ct);
        public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct) => inner.SetAttributesAsync(path, update, ct);
        public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct) => inner.GetStorageSpaceAsync(path, ct);
    }
}

public sealed record InMemoryStorageOptions
{
    public string Store { get; init; } = "default";
}

/// <summary>
/// The WebDAV server in memory (TestServer): <c>AddWebDav</c> and <c>MapWebDav</c> over the real storage factory (with the
/// permission, event and connection decorators), an in-memory user store, a recording event bus and a fake clock. The
/// header <see cref="RemoteIpHeader"/> sets the client address of a request (default loopback), <see cref="RawTargetHeader"/> its raw target.
/// </summary>
public sealed class WebDavTestHost : IAsyncDisposable
{
    public const string RemoteIpHeader = "X-Test-Remote-Ip";

    /// <summary>Sets the raw request target of a request, as Kestrel gives it for a URL that a client did not clean.</summary>
    public const string RawTargetHeader = "X-Test-Raw-Target";
    public const string Password = "Correct-Horse-42";

    private readonly WebApplication _app;

    private WebDavTestHost(WebApplication app, InMemoryStorageProvider provider, LogCapture logs)
    {
        _app = app;
        Provider = provider;
        Logs = logs;
    }

    /// <summary>The formatted log messages of the host.</summary>
    public LogCapture Logs { get; }

    public InMemoryStorageProvider Provider { get; }
    public InMemorySettingsRepository Repository => (InMemorySettingsRepository)_app.Services.GetRequiredService<ISettingsRepository>();
    public RecordingEventBus Events => (RecordingEventBus)_app.Services.GetRequiredService<IEventBus>();
    public IConnectionRegistry Connections => _app.Services.GetRequiredService<IConnectionRegistry>();
    public FakeTimeProvider Time => (FakeTimeProvider)_app.Services.GetRequiredService<TimeProvider>();

    /// <summary>The second factor: the ids of the users with TOTP.</summary>
    public FakeTwoFactor TwoFactor => (FakeTwoFactor)_app.Services.GetRequiredService<ITwoFactorVerifier>();
    internal WebDavSessionStore Sessions => _app.Services.GetRequiredService<WebDavSessionStore>();

    /// <summary>The storage of a user (each user has the store with its name).</summary>
    public InMemoryFileSystem StorageOf(string username) => Provider.Store(username);

    public static async Task<WebDavTestHost> StartAsync(StorageCapabilities capabilities = InMemoryFileSystem.AllCapabilities,
        IDictionary<string, string?>? settings = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Production" });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        var logs = new LogCapture();
        builder.Logging.AddProvider(logs);
        var configuration = new Dictionary<string, string?> { ["WebDav:Enabled"] = "true" };
        foreach (var (key, value) in settings ?? new Dictionary<string, string?>())
            configuration[key] = value;
        builder.Configuration.AddInMemoryCollection(configuration);

        var time = new FakeTimeProvider(new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero));
        var provider = new InMemoryStorageProvider(capabilities);
        var connections = new ConnectionRegistry(time);
        var events = new RecordingEventBus();
        var repository = new InMemorySettingsRepository(new ServerSettings());
        var registry = new SshServerModule.Storage.StorageProviderRegistry([provider]);
        var codec = new SshServerModule.Storage.StorageOptionsCodec(registry, new TestSecretProtector());
        var factory = new SshServerModule.Storage.StorageFileSystemFactory(registry, new PerUserResolver(codec), codec,
            new SshServer.Interfaces.Users.EffectiveUserSettingsService(repository), connections, events, time);

        builder.Services.AddSingleton<TimeProvider>(time);
        builder.Services.AddSingleton<ISettingsRepository>(repository);
        builder.Services.AddSingleton<IEventBus>(events);
        builder.Services.AddSingleton<IConnectionRegistry>(connections);
        builder.Services.AddSingleton<IFileSystemFactory>(factory);
        builder.Services.AddSingleton<ITwoFactorVerifier>(new FakeTwoFactor());
        builder.Services.AddWebDav(builder.Configuration);

        var app = builder.Build();
        app.Use((context, next) =>
        {
            context.Connection.RemoteIpAddress = IPAddress.Parse(
                context.Request.Headers.TryGetValue(RemoteIpHeader, out var ip) ? ip.ToString() : "127.0.0.1");
            if (context.Request.Headers.TryGetValue(RawTargetHeader, out var raw))
                context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpRequestFeature>()!.RawTarget = raw.ToString();
            return next(context);
        });
        app.MapWebDav();
        app.Run(context =>
        {
            context.Response.StatusCode = StatusCodes.Status418ImATeapot; // not a WebDAV request
            return Task.CompletedTask;
        });
        await app.StartAsync();
        return new WebDavTestHost(app, provider, logs);
    }

    /// <summary>Adds a user with <see cref="Password"/> (minimum PBKDF2 iterations, to keep the tests fast).</summary>
    public User AddUser(string username, Action<User>? configure = null)
    {
        var user = new User { Username = username, HashedPassword = PasswordHasher.Hash(Password, PasswordHasher.MinimumIterations) };
        configure?.Invoke(user);
        Repository.AddUser(user);
        return user;
    }

    /// <summary>A client of <paramref name="username"/> (Basic) at https://localhost/dav/.</summary>
    public HttpClient Client(string? username, string password = Password, string baseAddress = "https://localhost/")
    {
        var client = _app.GetTestServer().CreateClient();
        client.BaseAddress = new Uri(baseAddress);
        if (username != null)
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes(username + ":" + password)));
        return client;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }

    private sealed class PerUserResolver(SshServerModule.Storage.StorageOptionsCodec codec) : IUserStorageResolver
    {
        public UserStorage Resolve(User user) => new(codec.Encode("memory", new InMemoryStorageOptions { Store = user.Username }), []);
    }
}

/// <summary>
/// Keeps the formatted log messages of the server's own code (not of the Microsoft.* framework categories), to check
/// what a client can put in the log.
/// </summary>
public sealed class LogCapture : ILoggerProvider
{
    private readonly System.Collections.Concurrent.ConcurrentQueue<string> _messages = new();

    public IReadOnlyList<string> Messages => _messages.ToArray();

    public ILogger CreateLogger(string categoryName) =>
        categoryName.StartsWith("Microsoft.", StringComparison.Ordinal) ? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance : new Logger(this);

    public void Dispose()
    {
    }

    private sealed class Logger(LogCapture owner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            owner._messages.Enqueue(formatter(state, exception));
    }
}

/// <summary>A second factor for the tests: the users in <see cref="UserIds"/> have TOTP.</summary>
public sealed class FakeTwoFactor : ITwoFactorVerifier
{
    public HashSet<int> UserIds { get; } = new();

    public Task<bool> IsEnabledAsync(TwoFactorSubject subject, CancellationToken ct) =>
        Task.FromResult(subject.Kind == TwoFactorSubjectKind.User && UserIds.Contains(subject.Id));

    public Task<TwoFactorCheck> VerifyAsync(TwoFactorSubject subject, string? code, CancellationToken ct) =>
        Task.FromResult(TwoFactorCheck.Invalid);
}

/// <summary>Builders for the WebDAV requests of the tests.</summary>
public static class Dav
{
    public static HttpRequestMessage Request(string method, string url, string? body = null, params (string Name, string Value)[] headers)
    {
        var request = new HttpRequestMessage(new HttpMethod(method), url);
        if (body != null)
            request.Content = new StringContent(body, Encoding.UTF8, "application/xml");
        foreach (var (name, value) in headers)
            request.Headers.TryAddWithoutValidation(name, value);
        return request;
    }

    public static Task<HttpResponseMessage> SendAsync(this HttpClient client, string method, string url, string? body = null,
        params (string Name, string Value)[] headers) => client.SendAsync(Request(method, url, body, headers));

    public static async Task<HttpResponseMessage> PutAsync(this HttpClient client, string url, string content, params (string Name, string Value)[] headers)
    {
        var request = Request("PUT", url, null, headers);
        request.Content = new StringContent(content, Encoding.UTF8, "text/plain");
        return await client.SendAsync(request);
    }

    public const string LockBody = """
        <?xml version="1.0" encoding="utf-8"?>
        <D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype>
        <D:owner><D:href>litmus test suite</D:href></D:owner></D:lockinfo>
        """;

    public const string SharedLockBody = """
        <?xml version="1.0" encoding="utf-8"?>
        <D:lockinfo xmlns:D="DAV:"><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>
        """;
}
