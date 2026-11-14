using System.Net;
using System.Net.Sockets;
using System.Text;
using FxSsh.SshServerModule;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Renci.SshNet;
using SshServer.Filesystem.LocalDisk;
using SshServerModule.Storage;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Infrastructure;

/// <summary>
/// Starts the real SFTP server (<see cref="HostedServer"/>) in-process for one test class.
///
/// Layout of the temporary directory (unique for each fixture):
/// <code>
///   &lt;TempDirectory&gt;/config.db   a "secret" file OUTSIDE the user root (SecretFilePath)
///   &lt;TempDirectory&gt;/root/       the user root directory of test_person (UserRoot), "/" for the client
/// </code>
/// Each fixture has its own free TCP port, so test classes can run in parallel.
/// Use it with <c>IClassFixture&lt;SftpServerFixture&gt;</c>.
/// </summary>
public class SftpServerFixture : IAsyncLifetime
{
    public const string Host = "127.0.0.1";
    public const string SecretContent = "SECRET-CONFIG-DB-CONTENT-must-never-be-readable";

    private HostedServer? _server;
    private InMemorySettingsRepository? _repository;

    public int Port { get; private set; }
    /// <summary><c>ServerSettings.IdleTimeout</c> in seconds. Override it in a derived fixture.</summary>
    protected virtual int IdleTimeoutSeconds => 600;
    /// <summary>Changes the server settings before the server starts. Override it in a derived fixture.</summary>
    protected virtual void ConfigureSettings(ServerSettings settings)
    {
    }
    /// <summary>Configuration of the listen port and bind addresses (overrides the stored settings). Override it in a derived fixture.</summary>
    protected virtual SshServerOptions? CreateListenOptions(int port) => null;
    /// <summary>The clock of the server (bans, LastSuccessfulLogin). Override it with a FakeTimeProvider.</summary>
    protected virtual TimeProvider CreateTimeProvider() => TimeProvider.System;
    /// <summary>The auto-ban state of the running server.</summary>
    public LoginBanTracker BanTracker { get; private set; } = null!;
    public string TempDirectory { get; }
    public string UserRoot { get; }
    public string SecretFilePath { get; }
    public string Username => TestCredentials.Username;
    public string Password => TestCredentials.Password;

    /// <summary>The settings repository of the running server, to add users or read what the server stored.</summary>
    public InMemorySettingsRepository Repository =>
        _repository ?? throw new InvalidOperationException("The server is not started.");

    public SftpServerFixture()
    {
        TempDirectory = Path.Combine(Path.GetTempPath(), "freesftpsharp-tests", Guid.NewGuid().ToString("N"));
        UserRoot = Path.Combine(TempDirectory, "root");
        SecretFilePath = Path.Combine(TempDirectory, "config.db");
    }

    public async ValueTask InitializeAsync()
    {
        Directory.CreateDirectory(UserRoot);
        File.WriteAllText(SecretFilePath, SecretContent);

        // Another process can take the port between GetFreeTcpPort and StartAsync, so try a few times.
        Exception? lastError = null;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var port = GetFreeTcpPort();
            var server = CreateServer(port);
            try
            {
                await server.StartAsync(CancellationToken.None);
            }
            catch (SocketException ex)
            {
                lastError = ex;
                continue;
            }

            _server = server;
            _repository = (InMemorySettingsRepository)server._settingsRepository;
            Port = port;
            await WaitUntilServerAnswersAsync(port, TimeSpan.FromSeconds(15));
            return;
        }

        throw new InvalidOperationException("Could not start the test SFTP server on a free port.", lastError);
    }

    public virtual async ValueTask DisposeAsync()
    {
        if (_server != null)
        {
            try
            {
                await _server.StopAsync(CancellationToken.None);
            }
            catch
            {
                // The server can already be stopped. Cleanup must not fail the test run.
            }
            _server = null;
        }

        try
        {
            Directory.Delete(TempDirectory, recursive: true);
        }
        catch
        {
            // A file can still be open for a short time (for example on Windows). The OS cleans the temp directory.
        }
    }

    /// <summary>Creates a client that is not connected yet.</summary>
    public SftpClient CreateClient(string? password = null, string? username = null)
    {
        var client = new SftpClient(Host, Port, username ?? Username, password ?? Password);
        client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(15);
        client.OperationTimeout = TimeSpan.FromSeconds(30);
        return client;
    }

    /// <summary>Creates a connected client.</summary>
    public SftpClient Connect()
    {
        var client = CreateClient();
        client.Connect();
        return client;
    }

    /// <summary>The physical path of a virtual path such as "/dir/file.txt".</summary>
    public string PhysicalPath(string virtualPath)
    {
        return Path.Combine(UserRoot, virtualPath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar));
    }

    /// <summary>Creates a new, empty directory in the user root and returns its virtual path, for example "/t-1a2b...".</summary>
    public string CreateUniqueDirectory(string prefix = "t")
    {
        var name = $"{prefix}-{Guid.NewGuid():N}";
        Directory.CreateDirectory(Path.Combine(UserRoot, name));
        return "/" + name;
    }

    /// <summary>Adds a user with the same root directory as the default test user.</summary>
    public void AddUser(string username, string hashedPassword)
    {
        Repository.AddUser(new User
        {
            Username = username,
            HashedPassword = hashedPassword,
            UserRootDirectory = UserRoot,
            OnlyWhitelistedIps = false,
            WhitelistedIps = new List<string>(),
        });
    }

    private HostedServer CreateServer(int port)
    {
        var settings = new ServerSettings
        {
            ServerRsaKey = TestCredentials.HostKey,
            ListenToPort = port,
            ServerBanner = "FreeSftpSharpTests",
            IdleTimeout = IdleTimeoutSeconds,
            BindToAddress = new List<string>(),
            BlacklistedIps = new List<string>(),
            EnableCommand = false,
            EnableDirectTcpIp = false,
        };
        ConfigureSettings(settings);

        var repository = new InMemorySettingsRepository(settings);
        repository.AddUser(new User
        {
            Username = TestCredentials.Username,
            HashedPassword = TestCredentials.HashPassword(TestCredentials.Password),
            UserRootDirectory = UserRoot,
            OnlyWhitelistedIps = false,
            WhitelistedIps = new List<string>(),
        });

        BanTracker = new LoginBanTracker(CreateTimeProvider());
        return new HostedServer(NullLogger<HostedServer>.Instance, CreateFileSystemFactory(), repository, BanTracker,
            CreateListenOptions(port) is { } listenOptions ? Microsoft.Extensions.Options.Options.Create(listenOptions) : null);
    }

    /// <summary>
    /// The storage of the users. The default is the one of the hosts: the "local" provider at the user root
    /// (AddSshServerStorage + AddLocalDiskStorage). Override it in a derived fixture for another backend.
    /// </summary>
    protected virtual IFileSystemFactory CreateFileSystemFactory()
        => new StorageFileSystemFactory(new StorageProviderRegistry([new LocalDiskStorageProvider()]), new UserRootStorageResolver());

    private static int GetFreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>
    /// Opens a TCP connection and returns what the server sends first: its SSH identification line, or an
    /// empty string when the server closes the connection without sending anything.
    /// </summary>
    public async Task<string> ReadIdentificationAsync(IPAddress? address = null)
    {
        using var tcp = new TcpClient(address?.AddressFamily ?? AddressFamily.InterNetwork);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await tcp.ConnectAsync(address ?? IPAddress.Loopback, Port, cts.Token);
        var buffer = new byte[256];
        try
        {
            var read = await tcp.GetStream().ReadAsync(buffer, cts.Token);
            return Encoding.ASCII.GetString(buffer, 0, read);
        }
        catch (IOException)
        {
            return ""; // connection reset by the server
        }
    }

    /// <summary>Waits until the server accepts a TCP connection and sends its SSH identification line.</summary>
    private static async Task WaitUntilServerAnswersAsync(int port, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        Exception? lastError = null;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var tcp = new TcpClient();
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await tcp.ConnectAsync(IPAddress.Loopback, port, cts.Token);
                var buffer = new byte[64];
                var read = await tcp.GetStream().ReadAsync(buffer, cts.Token);
                if (read > 0 && Encoding.ASCII.GetString(buffer, 0, read).StartsWith("SSH-", StringComparison.Ordinal))
                    return;
            }
            catch (Exception ex)
            {
                lastError = ex;
            }
            await Task.Delay(50);
        }

        throw new TimeoutException($"The test SFTP server on port {port} did not answer within {timeout}.", lastError);
    }
}
