using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using Renci.SshNet;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// "From download to login in two commands": the real, built <c>ServerConsoleApp</c> runs <c>user add</c> in an empty
/// directory (no configuration, no database), the password comes through stdin, and the command exits. Then the
/// server is started and SSH.NET logs in with that user. Also <c>user list</c> and <c>user remove</c> as processes.
/// </summary>
public class UserCommandEndToEndTests : IAsyncLifetime
{
    private readonly string _temp = Path.Combine(Path.GetTempPath(), "freesftpsharp-usercmd-" + Guid.NewGuid().ToString("N"));
    private Process? _server;

    private string AppDir => Path.Combine(_temp, "app");
    private string UserRoot => Path.Combine(_temp, "files", "alice"); // does not exist: the command creates it

    public ValueTask InitializeAsync()
    {
        Directory.CreateDirectory(AppDir);
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        try
        {
            if (_server is { HasExited: false })
            {
                _server.Kill(entireProcessTree: true);
                _server.WaitForExit(10_000);
            }
        }
        catch
        {
            // Already gone.
        }
        _server?.Dispose();
        try { Directory.Delete(_temp, recursive: true); } catch { /* the OS cleans the temp directory */ }
        return ValueTask.CompletedTask;
    }

    [Fact]
    public async Task User_add_in_an_empty_directory_gives_a_user_that_can_log_in()
    {
        var ct = TestContext.Current.CancellationToken;
        CopyBuildOutput(FindBuildOutput(), AppDir);
        Assert.Empty(Directory.GetFiles(AppDir, "*.db"));

        var add = await RunAppAsync("my secret pw\n", ct, "user", "add", "alice", "--root", UserRoot, "--password-stdin");

        Assert.True(add.ExitCode == 0, add.ToString());
        Assert.DoesNotContain("my secret pw", add.Output + add.Error);
        Assert.True(Directory.Exists(UserRoot), "the root directory was not created");
        Assert.True(File.Exists(Path.Combine(AppDir, "freesftpsharp.db")), "the command did not use the default settings database");
        Assert.False(Directory.Exists(Path.Combine(AppDir, "logs")), "the command must not start the server or its logging");

        var list = await RunAppAsync("", ct, "user", "list");
        Assert.Equal(0, list.ExitCode);
        Assert.Contains("alice", list.Output);
        Assert.Contains(UserRoot, list.Output);

        var duplicate = await RunAppAsync("my secret pw\n", ct, "user", "add", "ALICE", "--root", UserRoot, "--password-stdin");
        Assert.Equal(1, duplicate.ExitCode);
        Assert.Contains("already exists", duplicate.Error);

        var port = GetFreeTcpPort();
        StartServer(port);
        await WaitForSshBannerAsync(port, TimeSpan.FromSeconds(90), ct);

        using (var client = new SftpClient("127.0.0.1", port, "alice", "my secret pw"))
        {
            client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(30);
            client.OperationTimeout = TimeSpan.FromSeconds(30);
            client.Connect();
            using var upload = new MemoryStream(Encoding.UTF8.GetBytes("hello"));
            client.UploadFile(upload, "/hello.txt");
            Assert.Equal("hello", await File.ReadAllTextAsync(Path.Combine(UserRoot, "hello.txt"), ct));
            client.Disconnect();
        }

        // Removed while the server runs: the next login fails.
        var remove = await RunAppAsync("", ct, "user", "remove", "alice");
        Assert.Equal(0, remove.ExitCode);
        using (var client = new SftpClient("127.0.0.1", port, "alice", "my secret pw"))
        {
            client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(30);
            Assert.ThrowsAny<Exception>(() => client.Connect());
        }
    }

    private sealed record AppResult(int ExitCode, string Output, string Error)
    {
        public override string ToString() => $"exit {ExitCode}{Environment.NewLine}{Output}{Environment.NewLine}{Error}";
    }

    private ProcessStartInfo CreateStartInfo(params string[] args)
    {
        var info = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = _temp,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
        };
        info.ArgumentList.Add(Path.Combine(AppDir, "ServerConsoleApp.dll"));
        foreach (var arg in args)
            info.ArgumentList.Add(arg);
        foreach (var key in info.Environment.Keys.Where(k => k.StartsWith("SshServer__", StringComparison.OrdinalIgnoreCase)
                     || k.StartsWith("Serilog__", StringComparison.OrdinalIgnoreCase)
                     || k.StartsWith("Settings__", StringComparison.OrdinalIgnoreCase)
                     || k.StartsWith("ConnectionStrings__", StringComparison.OrdinalIgnoreCase)).ToList())
            info.Environment.Remove(key);
        return info;
    }

    private async Task<AppResult> RunAppAsync(string stdin, CancellationToken ct, params string[] args)
    {
        using var process = Process.Start(CreateStartInfo(args))!;
        var output = process.StandardOutput.ReadToEndAsync(ct);
        var error = process.StandardError.ReadToEndAsync(ct);
        await process.StandardInput.WriteAsync(stdin);
        process.StandardInput.Close();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(3)); // the first start makes an RSA 4096 host key
        await process.WaitForExitAsync(timeout.Token);
        return new AppResult(process.ExitCode, await output, await error);
    }

    private void StartServer(int port)
    {
        var info = CreateStartInfo("--port", port.ToString());
        info.RedirectStandardInput = false;
        _server = new Process { StartInfo = info };
        _server.OutputDataReceived += (_, _) => { };
        _server.ErrorDataReceived += (_, _) => { };
        _server.Start();
        _server.BeginOutputReadLine();
        _server.BeginErrorReadLine();
    }

    private async Task WaitForSshBannerAsync(int port, TimeSpan timeout, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (_server!.HasExited)
                throw new InvalidOperationException("ServerConsoleApp exited with code " + _server.ExitCode);
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
        throw new TimeoutException("ServerConsoleApp did not answer on port " + port);
    }

    private static string FindBuildOutput()
    {
        var dir = typeof(UserCommandEndToEndTests).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
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

    private static bool IsRuntimeData(string relativePath) =>
        relativePath.StartsWith("logs", StringComparison.OrdinalIgnoreCase)
        || relativePath.EndsWith(".db", StringComparison.OrdinalIgnoreCase)
        || relativePath.EndsWith(".db-wal", StringComparison.OrdinalIgnoreCase)
        || relativePath.EndsWith(".db-shm", StringComparison.OrdinalIgnoreCase);

    private static int GetFreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try { return ((IPEndPoint)listener.LocalEndpoint).Port; }
        finally { listener.Stop(); }
    }
}
