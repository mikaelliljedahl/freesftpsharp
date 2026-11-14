using System.Diagnostics;

namespace FreeSftpSharp.Tests.Ftp;

/// <summary>
/// curl (--ssl-reqd) and lftp (ftp:ssl-force) against the FTP server over FTPS: list, upload, download, resume, rename
/// and delete (issue #72). Each test is skipped when its tool is not on PATH; the Ubuntu job of CI has both. They are
/// skipped on Windows (curl there uses Schannel, which is not verified with the self-signed certificate).
/// </summary>
public sealed class FtpCommandLineClientTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("ftp-cli-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static string? Find(string tool)
    {
        if (OperatingSystem.IsWindows())
            return null;
        return (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator)
            .Select(dir => Path.Combine(dir, tool)).FirstOrDefault(File.Exists);
    }

    private static async Task<(int ExitCode, string Output)> RunAsync(string tool, params string[] arguments)
    {
        var start = new ProcessStartInfo(tool) { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start)!;
        process.StandardInput.Close();
        var output = process.StandardOutput.ReadToEndAsync(Ct);
        var error = process.StandardError.ReadToEndAsync(Ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw;
        }
        return (process.ExitCode, await output + await error);
    }

    [Fact]
    public async Task Curl_lists_uploads_downloads_resumes_renames_and_deletes_over_ftps()
    {
        var curl = Find("curl");
        if (curl == null)
            Assert.Skip("curl is not on PATH (or the OS is Windows).");
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("alice");
        var url = $"ftp://127.0.0.1:{host.Port}";
        string[] common = ["-sS", "--ssl-reqd", "-k", "--user", "alice:" + FtpTestHost.Password];

        var data = new byte[200 * 1024];
        new Random(1).NextBytes(data);
        var local = Path.Combine(_directory, "data.bin");
        await File.WriteAllBytesAsync(local, data, Ct);
        await host.StorageOf("alice").WriteAllAsync("/partial.bin", data[..(50 * 1024)]);

        var run = await RunAsync(curl, [.. common, "--ftp-create-dirs", "-T", local, url + "/dir/data.bin"]);
        Assert.True(run.ExitCode == 0, run.Output);
        Assert.Equal(data, await host.StorageOf("alice").ReadAllAsync("/dir/data.bin"));

        run = await RunAsync(curl, [.. common, url + "/dir/"]);
        Assert.True(run.ExitCode == 0, run.Output);
        Assert.Contains("data.bin", run.Output);

        var downloaded = Path.Combine(_directory, "down.bin");
        run = await RunAsync(curl, [.. common, "-o", downloaded, url + "/dir/data.bin"]);
        Assert.True(run.ExitCode == 0, run.Output);
        Assert.Equal(data, await File.ReadAllBytesAsync(downloaded, Ct));

        // Resume the upload (SIZE, then APPE) and the download (REST).
        run = await RunAsync(curl, [.. common, "-C", "-", "-T", local, url + "/partial.bin"]);
        Assert.True(run.ExitCode == 0, run.Output);
        Assert.Equal(data, await host.StorageOf("alice").ReadAllAsync("/partial.bin"));
        var partial = Path.Combine(_directory, "partial.bin");
        await File.WriteAllBytesAsync(partial, data[..(120 * 1024)], Ct);
        run = await RunAsync(curl, [.. common, "-C", "-", "-o", partial, url + "/dir/data.bin"]);
        Assert.True(run.ExitCode == 0, run.Output);
        Assert.Equal(data, await File.ReadAllBytesAsync(partial, Ct));

        run = await RunAsync(curl, [.. common, "-Q", "RNFR /dir/data.bin", "-Q", "RNTO /dir/renamed.bin", "-Q", "DELE /partial.bin", url + "/"]);
        Assert.True(run.ExitCode == 0, run.Output);
        Assert.NotNull(await host.StorageOf("alice").StatAsync("/dir/renamed.bin", true, Ct));
        Assert.Null(await host.StorageOf("alice").StatAsync("/dir/data.bin", true, Ct));
        Assert.Null(await host.StorageOf("alice").StatAsync("/partial.bin", true, Ct));
    }

    [Fact]
    public async Task Curl_without_tls_is_refused_when_tls_is_required()
    {
        var curl = Find("curl");
        if (curl == null)
            Assert.Skip("curl is not on PATH (or the OS is Windows).");
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("alice");

        var run = await RunAsync(curl, "-sS", "--user", "alice:" + FtpTestHost.Password, $"ftp://127.0.0.1:{host.Port}/");
        Assert.NotEqual(0, run.ExitCode);
        Assert.Contains("530", run.Output);
    }

    [Fact]
    public async Task Lftp_lists_uploads_downloads_resumes_renames_and_deletes_over_ftps()
    {
        var lftp = Find("lftp");
        if (lftp == null)
            Assert.Skip("lftp is not on PATH (or the OS is Windows).");
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("alice");
        var data = new byte[200 * 1024];
        new Random(2).NextBytes(data);
        await File.WriteAllBytesAsync(Path.Combine(_directory, "data.bin"), data, Ct);
        await File.WriteAllBytesAsync(Path.Combine(_directory, "partial.bin"), data[..(70 * 1024)], Ct);
        await host.StorageOf("alice").WriteAllAsync("/resume.bin", data[..(30 * 1024)]);

        var script = string.Join("; ",
            "set ssl:verify-certificate no", "set ftp:ssl-force true", "set ftp:ssl-protect-data true", "set net:max-retries 1",
            $"lcd {_directory}", "put data.bin", "put -c data.bin -o resume.bin", "ls", "get -c data.bin -o partial.bin",
            "mv data.bin renamed.bin", "put data.bin -o gone.bin", "rm gone.bin", "bye");
        var run = await RunAsync(lftp, "-u", "alice," + FtpTestHost.Password, "-p", host.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "-e", script, "127.0.0.1");
        Assert.True(run.ExitCode == 0, run.Output);
        Assert.Contains("data.bin", run.Output);
        Assert.Equal(data, await host.StorageOf("alice").ReadAllAsync("/renamed.bin"));
        Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(_directory, "partial.bin"), Ct));
        Assert.Equal(data, await host.StorageOf("alice").ReadAllAsync("/resume.bin"));
        Assert.Null(await host.StorageOf("alice").StatAsync("/gone.bin", true, Ct));
    }
}
