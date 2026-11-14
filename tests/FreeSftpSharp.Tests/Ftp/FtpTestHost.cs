using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using FluentFTP;
using FreeSftpSharp.Ftp;
using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Storage;
using FreeSftpSharp.Tests.WebDav;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.TwoFactor;
using SshServerModule.Connections;
using SshServerModule.Quotas;

namespace FreeSftpSharp.Tests.Ftp;

/// <summary>
/// The FTP server in process: <c>AddFtp</c> over the real storage factory (permissions, quotas, bandwidth, events and
/// connection tracking), an in-memory user store and storage, and a recording event bus. It listens on 127.0.0.1 on a
/// free port, with a free passive port range, and TLS with a self-signed certificate (Required by default).
/// </summary>
public sealed class FtpTestHost : IAsyncDisposable
{
    public const string Password = "Correct-Horse-42";

    private readonly IHost _host;

    private FtpTestHost(IHost host, InMemoryStorageProvider provider, LogCapture logs, (int First, int Last) passive)
    {
        _host = host;
        Provider = provider;
        Logs = logs;
        PassivePorts = passive;
    }

    public LogCapture Logs { get; }
    public InMemoryStorageProvider Provider { get; }
    public (int First, int Last) PassivePorts { get; }
    public InMemorySettingsRepository Repository => (InMemorySettingsRepository)_host.Services.GetRequiredService<ISettingsRepository>();
    public RecordingEventBus Events => (RecordingEventBus)_host.Services.GetRequiredService<IEventBus>();
    public IConnectionRegistry Connections => _host.Services.GetRequiredService<IConnectionRegistry>();
    public FakeTwoFactor TwoFactor => (FakeTwoFactor)_host.Services.GetRequiredService<ITwoFactorVerifier>();
    public QuotaUsageTracker Quotas => _host.Services.GetRequiredService<QuotaUsageTracker>();
    public int Port => _host.Services.GetRequiredService<FreeSftpSharp.Ftp.FtpServer>().LocalEndPoints[0].Port;

    public InMemoryFileSystem StorageOf(string username) => Provider.Store(username);

    public static async Task<FtpTestHost> StartAsync(IDictionary<string, string?>? settings = null,
        StorageCapabilities capabilities = InMemoryFileSystem.AllCapabilities)
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = "Production", DisableDefaults = true });
        builder.Logging.ClearProviders();
        var logs = new LogCapture();
        builder.Logging.AddProvider(logs);
        var passive = FreePortRange(20);
        var configuration = new Dictionary<string, string?>
        {
            ["Ftp:Enabled"] = "true",
            ["Ftp:Port"] = "0",
            ["Ftp:BindAddresses:0"] = "127.0.0.1",
            ["Ftp:PassivePortRange"] = $"{passive.First}-{passive.Last}",
            ["Ftp:DataTimeoutSeconds"] = "10",
        };
        foreach (var (key, value) in settings ?? new Dictionary<string, string?>())
            configuration[key] = value;
        builder.Configuration.AddInMemoryCollection(configuration);

        var provider = new InMemoryStorageProvider(capabilities);
        var connections = new ConnectionRegistry(TimeProvider.System);
        var events = new RecordingEventBus();
        var repository = new InMemorySettingsRepository(new ServerSettings { MaxLoginAttemptsBeforeBan = 0 });
        var tracker = new QuotaUsageTracker(new InMemoryQuotaUsageStore());
        var registry = new SshServerModule.Storage.StorageProviderRegistry([provider]);
        var codec = new SshServerModule.Storage.StorageOptionsCodec(registry, new TestSecretProtector());
        var factory = new SshServerModule.Storage.StorageFileSystemFactory(registry, new PerUserResolver(codec), codec,
            new SshServer.Interfaces.Users.EffectiveUserSettingsService(repository), connections, events, TimeProvider.System,
            new QuotaDecorators(tracker));

        builder.Services.AddSingleton<ISettingsRepository>(repository);
        builder.Services.AddSingleton<IEventBus>(events);
        builder.Services.AddSingleton<IConnectionRegistry>(connections);
        builder.Services.AddSingleton<IFileSystemFactory>(factory);
        builder.Services.AddSingleton(tracker);
        builder.Services.AddSingleton<ITwoFactorVerifier>(new FakeTwoFactor());
        builder.Services.AddFtp(builder.Configuration);

        var host = builder.Build();
        await host.StartAsync();
        return new FtpTestHost(host, provider, logs, passive);
    }

    /// <summary>Adds a user with <see cref="Password"/> (minimum PBKDF2 iterations, to keep the tests fast).</summary>
    public User AddUser(string username, Action<User>? configure = null)
    {
        var user = new User { Username = username, HashedPassword = PasswordHasher.Hash(Password, PasswordHasher.MinimumIterations) };
        configure?.Invoke(user);
        Repository.AddUser(user);
        return user;
    }

    /// <summary>A FluentFTP client (not connected) with explicit TLS (or plain FTP), passive mode, any certificate accepted.</summary>
    public AsyncFtpClient Client(string username, string password = Password, bool tls = true,
        FtpDataConnectionType mode = FtpDataConnectionType.EPSV)
    {
        var client = new AsyncFtpClient("127.0.0.1", username, password, Port);
        client.Config.EncryptionMode = tls ? FtpEncryptionMode.Explicit : FtpEncryptionMode.None;
        client.Config.ValidateAnyCertificate = true;
        client.Config.DataConnectionType = mode;
        client.Config.ConnectTimeout = 10000;
        client.Config.ReadTimeout = 10000;
        client.Config.DataConnectionConnectTimeout = 10000;
        client.Config.DataConnectionReadTimeout = 10000;
        client.Config.RetryAttempts = 1;
        return client;
    }

    /// <summary>A raw control connection, for the protocol tests.</summary>
    public async Task<FtpRawClient> RawAsync()
    {
        var raw = new FtpRawClient();
        await raw.ConnectAsync(Port);
        return raw;
    }

    public async ValueTask DisposeAsync()
    {
        await _host.StopAsync();
        _host.Dispose();
    }

    /// <summary><paramref name="count"/> consecutive ports that are free now.</summary>
    internal static (int First, int Last) FreePortRange(int count)
    {
        for (var attempt = 0; attempt < 50; attempt++)
        {
            var first = Random.Shared.Next(20000, 60000 - count);
            var free = true;
            for (var port = first; port < first + count && free; port++)
            {
                try
                {
                    var probe = new TcpListener(IPAddress.Loopback, port);
                    probe.Start();
                    probe.Stop();
                }
                catch (SocketException)
                {
                    free = false;
                }
            }
            if (free)
                return (first, first + count - 1);
        }
        throw new InvalidOperationException("No free port range.");
    }

    private sealed class PerUserResolver(SshServerModule.Storage.StorageOptionsCodec codec) : IUserStorageResolver
    {
        public UserStorage Resolve(User user) => new(codec.Encode("memory", new InMemoryStorageOptions { Store = user.Username }), []);
    }
}

/// <summary>A raw FTP control connection: send lines, read replies (multi-line aware), switch to TLS.</summary>
public sealed class FtpRawClient : IAsyncDisposable
{
    private readonly TcpClient _tcp = new();
    private Stream _stream = Stream.Null;
    private StreamReader _reader = StreamReader.Null;

    public async Task ConnectAsync(int port)
    {
        await _tcp.ConnectAsync(IPAddress.Loopback, port);
        _stream = _tcp.GetStream();
        _reader = new StreamReader(_stream, new UTF8Encoding(false), false, 1);
    }

    /// <summary>Sends a line with CRLF.</summary>
    public async Task SendAsync(string line)
    {
        var bytes = Encoding.UTF8.GetBytes(line + "\r\n");
        await _stream.WriteAsync(bytes);
        await _stream.FlushAsync();
    }

    public Task SendBytesAsync(byte[] bytes) => _stream.WriteAsync(bytes).AsTask();

    /// <summary>The next reply: its code and all its lines. Code 0 when the server closed the connection.</summary>
    public async Task<(int Code, string Text)> ReadAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var first = await _reader.ReadLineAsync(timeout.Token);
        if (first == null)
            return (0, "");
        var code = int.Parse(first[..3], System.Globalization.CultureInfo.InvariantCulture);
        var text = new StringBuilder(first);
        if (first.Length > 3 && first[3] == '-')
        {
            while (true)
            {
                var line = await _reader.ReadLineAsync(timeout.Token) ?? throw new IOException("closed in a multi-line reply");
                text.Append('\n').Append(line);
                if (line.StartsWith(first[..3] + " ", StringComparison.Ordinal))
                    break;
            }
        }
        return (code, text.ToString());
    }

    public async Task<(int Code, string Text)> CommandAsync(string line)
    {
        await SendAsync(line);
        return await ReadAsync();
    }

    /// <summary>AUTH TLS and the client side of the handshake (any certificate).</summary>
    public async Task StartTlsAsync()
    {
        var (code, _) = await CommandAsync("AUTH TLS");
        Assert.Equal(234, code);
        var ssl = new SslStream(_stream, false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync("localhost");
        _stream = ssl;
        _reader = new StreamReader(_stream, new UTF8Encoding(false), false, 1);
    }

    /// <summary>True when the server closed the connection (the next read gives no data).</summary>
    public async Task<bool> IsClosedAsync()
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            return await _reader.ReadLineAsync(timeout.Token) == null;
        }
        catch (IOException)
        {
            return true;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stream.DisposeAsync();
        _tcp.Dispose();
    }
}

/// <summary>Reads and writes whole files of a storage, for the FTP tests.</summary>
public static class FtpStorage
{
    public static Task WriteAllAsync(this IFileSystem fs, string path, string text) => fs.WriteAllAsync(path, Encoding.UTF8.GetBytes(text));

    public static async Task WriteAllAsync(this IFileSystem fs, string path, byte[] data)
    {
        await using var handle = await fs.OpenAsync(path, FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate, null, CancellationToken.None);
        if (data.Length > 0)
            await handle.WriteAsync(0, data, CancellationToken.None);
    }

    public static async Task<byte[]> ReadAllAsync(this IFileSystem fs, string path)
    {
        await using var handle = await fs.OpenAsync(path, FileOpenFlags.Read, null, CancellationToken.None);
        using var result = new MemoryStream();
        var buffer = new byte[64 * 1024];
        int read;
        while ((read = await handle.ReadAsync(result.Length, buffer, CancellationToken.None)) > 0)
            result.Write(buffer, 0, read);
        return result.ToArray();
    }

    public static async Task<string> ReadAllTextAsync(this IFileSystem fs, string path) => Encoding.UTF8.GetString(await fs.ReadAllAsync(path));
}
