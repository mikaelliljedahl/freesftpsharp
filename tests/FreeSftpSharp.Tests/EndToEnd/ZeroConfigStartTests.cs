using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Renci.SshNet;
using SshServer.Interfaces;
using SshServer.Settings.Sql;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// The server must work as a simple local test server with ZERO configuration.
/// This starts the real, built <c>ServerConsoleApp</c> as a process, from a copy of its build output in a fresh
/// temporary directory: no appsettings override, no database file, no host keys. The only argument is
/// <c>--port</c> with a free port (the stored default is 22, which a test cannot use).
///
/// What a new local user has to do to get started:
/// <list type="number">
///   <item>Run <c>ServerConsoleApp</c>. It creates <c>freesftpsharp.db</c> (SQLite) next to the app, with the
///   RSA and ECDSA host keys and the default settings (port 22; use <c>--port</c> to change it).</item>
///   <item>Add one user. There is no default user, so nobody can log in before this. Use the admin UI
///   (FxSshSftpServer, page Users) or, as this test does, <c>SqlSettingsRepository.AddUser</c> with a user name,
///   a password hash from <c>PasswordHasher.Hash</c> and a <c>UserRootDirectory</c> that exists. The running
///   server reads users from the database on every login, so no restart is needed.</item>
///   <item>Connect with any SFTP client to the port with that user and password.</item>
/// </list>
/// </summary>
public class ZeroConfigStartTests : IAsyncLifetime
{
    private readonly string _temp = Path.Combine(Path.GetTempPath(), "freesftpsharp-zeroconfig-" + Guid.NewGuid().ToString("N"));
    private readonly StringBuilder _output = new();
    private Process? _process;

    private string AppDir => Path.Combine(_temp, "app");
    private string UserRoot => Path.Combine(_temp, "root");

    public ValueTask InitializeAsync()
    {
        Directory.CreateDirectory(AppDir);
        Directory.CreateDirectory(UserRoot);
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        try
        {
            if (_process is { HasExited: false })
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(10_000);
            }
        }
        catch
        {
            // Already gone.
        }
        _process?.Dispose();

        try
        {
            Directory.Delete(_temp, recursive: true);
        }
        catch
        {
            // A file can still be open for a short time. The OS cleans the temp directory.
        }
        return ValueTask.CompletedTask;
    }

    [Fact]
    public async Task Server_starts_without_any_configuration_and_serves_a_new_user()
    {
        var ct = TestContext.Current.CancellationToken;
        CopyBuildOutput(FindBuildOutput(), AppDir);
        Assert.Empty(Directory.GetFiles(AppDir, "*.db"));
        Assert.False(Directory.Exists(Path.Combine(AppDir, "logs")));

        var port = GetFreeTcpPort();
        StartApp(port);
        await WaitForSshBannerAsync(port, TimeSpan.FromSeconds(90), ct);

        // The server made its database and host keys itself.
        var dbPath = Path.Combine(AppDir, "freesftpsharp.db");
        Assert.True(File.Exists(dbPath), "freesftpsharp.db was not created");
        var options = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite($"Data Source={dbPath};Pooling=False").Options;
        using (var repository = new SqlSettingsRepository(options))
        {
            Assert.False(string.IsNullOrWhiteSpace(repository.ServerSettings.ServerRsaKey), "no RSA host key was stored");
            Assert.False(string.IsNullOrWhiteSpace(repository.ServerSettings.ServerEcdsaKey), "no ECDSA host key was stored");
            Assert.Null(repository.GetUser("local")); // no default user

            // There is no default user: a new local user has to be added (see the class comment).
            Assert.True(repository.AddUser(new User
            {
                Username = "local",
                HashedPassword = TestCredentials.HashPassword("local-secret"),
                UserRootDirectory = UserRoot,
                OnlyWhitelistedIps = false,
                WhitelistedIps = new List<string>(),
            }));
        }

        using (var client = new SftpClient("127.0.0.1", port, "local", "local-secret"))
        {
            client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(30);
            client.OperationTimeout = TimeSpan.FromSeconds(30);
            client.Connect();

            var content = "zero config " + Guid.NewGuid();
            using (var upload = new MemoryStream(Encoding.UTF8.GetBytes(content)))
                client.UploadFile(upload, "/hello.txt");

            var names = client.ListDirectory("/").Select(f => f.Name).ToList();
            Assert.Contains("hello.txt", names);
            Assert.Equal(content, await File.ReadAllTextAsync(Path.Combine(UserRoot, "hello.txt"), ct));
            client.Disconnect();
        }

        // Stop the app so the log file is complete, then check what it logged.
        _process!.Kill(entireProcessTree: true);
        await _process.WaitForExitAsync(ct);
        var console = StripAnsi(_output.ToString());
        var logFile = Path.Combine(AppDir, "logs", "FxSshServer.txt");
        Assert.True(File.Exists(logFile), "the log file was not created in the app directory");
        string fileLog;
        using (var stream = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        using (var reader = new StreamReader(stream))
            fileLog = await reader.ReadToEndAsync(ct);

        Assert.Contains("Starting host service", console);
        var problems = (console + Environment.NewLine + fileLog)
            .Split('\n')
            .Where(l => Regex.IsMatch(l, @"\b(ERR|FTL|Error|Fatal)\b|\[ERR\]|\[FTL\]|Unhandled exception"))
            .ToList();
        Assert.True(problems.Count == 0, "The start logged errors:" + Environment.NewLine + string.Join(Environment.NewLine, problems));
    }

    private void StartApp(int port)
    {
        var dll = Path.Combine(AppDir, "ServerConsoleApp.dll");
        var info = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = _temp, // not the app directory: everything must be found next to the app
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        info.ArgumentList.Add(dll);
        info.ArgumentList.Add("--port");
        info.ArgumentList.Add(port.ToString());
        // No inherited configuration that could change the start.
        foreach (var key in info.Environment.Keys.Where(k => k.StartsWith("SshServer__", StringComparison.OrdinalIgnoreCase)
                     || k.StartsWith("Serilog__", StringComparison.OrdinalIgnoreCase)
                     || k.StartsWith("Settings__", StringComparison.OrdinalIgnoreCase)
                     || k.StartsWith("ConnectionStrings__", StringComparison.OrdinalIgnoreCase)).ToList())
            info.Environment.Remove(key);

        _process = new Process { StartInfo = info };
        _process.OutputDataReceived += (_, e) => { if (e.Data != null) lock (_output) _output.AppendLine(e.Data); };
        _process.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (_output) _output.AppendLine("[stderr] " + e.Data); };
        _process.Start();
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();
    }

    private async Task WaitForSshBannerAsync(int port, TimeSpan timeout, CancellationToken ct)
    {
        // The first start makes an RSA 4096 key, which takes a while.
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (_process!.HasExited)
                throw new InvalidOperationException("ServerConsoleApp exited with code " + _process.ExitCode + Environment.NewLine + _output);
            try
            {
                using var tcp = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(5));
                await tcp.ConnectAsync(IPAddress.Loopback, port, cts.Token);
                var buffer = new byte[64];
                var read = await tcp.GetStream().ReadAsync(buffer, cts.Token);
                if (read > 0 && Encoding.ASCII.GetString(buffer, 0, read).StartsWith("SSH-", StringComparison.Ordinal))
                    return;
            }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
            }
            await Task.Delay(100, ct);
        }
        throw new TimeoutException("ServerConsoleApp did not answer on port " + port + Environment.NewLine + _output);
    }

    private static string FindBuildOutput()
    {
        var dir = typeof(ZeroConfigStartTests).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Single(a => a.Key == "ServerConsoleAppOutput").Value!;
        Assert.True(File.Exists(Path.Combine(dir, "ServerConsoleApp.dll")), "ServerConsoleApp is not built in " + dir);
        return dir;
    }

    private static void CopyBuildOutput(string source, string target)
    {
        foreach (var dir in Directory.GetDirectories(source, "*", SearchOption.AllDirectories))
        {
            if (IsRuntimeData(Path.GetRelativePath(source, dir))) continue;
            Directory.CreateDirectory(Path.Combine(target, Path.GetRelativePath(source, dir)));
        }
        foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(source, file);
            if (IsRuntimeData(relative)) continue;
            File.Copy(file, Path.Combine(target, relative));
        }
    }

    // Data of an earlier manual run in the build directory is not part of the program.
    private static bool IsRuntimeData(string relativePath) =>
        relativePath.StartsWith("logs", StringComparison.OrdinalIgnoreCase)
        || relativePath.EndsWith(".db", StringComparison.OrdinalIgnoreCase)
        || relativePath.EndsWith(".db-wal", StringComparison.OrdinalIgnoreCase)
        || relativePath.EndsWith(".db-shm", StringComparison.OrdinalIgnoreCase);

    private static string StripAnsi(string text) => Regex.Replace(text, "\u001b\\[[0-9;]*m", "");

    private static int GetFreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try { return ((IPEndPoint)listener.LocalEndpoint).Port; }
        finally { listener.Stop(); }
    }
}
