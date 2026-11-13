using System.Diagnostics;
using System.Text;

namespace FreeSftpSharp.Tests.Infrastructure;

/// <summary>
/// Runs the OpenSSH <c>sftp</c> command line client against the test server.
///
/// The password comes from an SSH_ASKPASS script (SSH_ASKPASS_REQUIRE=force), and the commands are
/// written to stdin. "sftp -b" cannot be used, because batch mode turns off password authentication.
/// Without -b, sftp continues after a failed command, so the tests check the result on disk and in the output.
/// </summary>
public static class OpenSshSftp
{
    /// <summary>Set this environment variable to "1" to run the OpenSSH tests on Windows too.</summary>
    public const string WindowsOptInVariable = "FREESFTPSHARP_OPENSSH_ON_WINDOWS";

    private static readonly Lazy<string?> SftpPath = new(FindSftpOnPath);

    public static string? SkipReason
    {
        get
        {
            if (OperatingSystem.IsWindows() && Environment.GetEnvironmentVariable(WindowsOptInVariable) != "1")
                return "The OpenSSH sftp tests are not verified on Windows (Win32-OpenSSH askpass with a .cmd script). " +
                       $"Set {WindowsOptInVariable}=1 to run them.";
            if (SftpPath.Value == null)
                return "OpenSSH sftp is not on PATH.";
            return null;
        }
    }

    /// <summary>Call this first in every OpenSSH test.</summary>
    public static void SkipIfUnavailable()
    {
        var reason = SkipReason;
        if (reason != null)
            Assert.Skip(reason);
    }

    /// <param name="ExitedByItself">
    /// False when the harness had to stop sftp after the last command (see <see cref="RunAsync"/>).
    /// </param>
    public sealed record Result(bool ExitedByItself, int? ExitCode, string StandardOutput, string StandardError)
    {
        public string AllOutput => StandardOutput + Environment.NewLine + StandardError;
        public override string ToString() =>
            $"exited by itself: {ExitedByItself}, exit code: {ExitCode?.ToString() ?? "-"}{Environment.NewLine}" +
            $"stdout:{Environment.NewLine}{StandardOutput}{Environment.NewLine}stderr:{Environment.NewLine}{StandardError}";
    }

    /// <summary>The line that the "lpwd" command prints. RunAsync adds "lpwd" after the last command.</summary>
    private const string DoneMarker = "Local working directory:";

    /// <summary>
    /// How long sftp gets to exit by itself after the last command, before the harness stops it.
    /// </summary>
    public static readonly TimeSpan DefaultExitGracePeriod = TimeSpan.FromMilliseconds(500);

    /// <summary>
    /// Runs sftp with <paramref name="commands"/> (one per line) and the local working directory
    /// <paramref name="localDirectory"/>.
    ///
    /// RunAsync adds "lpwd" after the commands and waits for its output (then all commands are done, because
    /// sftp runs them in order). sftp normally exits by itself at the end of stdin; if it does not exit within
    /// <paramref name="exitGracePeriod"/>, the harness stops the process tree, so a server that does not close
    /// the channel cannot hang the suite. <see cref="Result.ExitedByItself"/> tells which case happened.
    /// </summary>
    public static async Task<Result> RunAsync(SftpServerFixture server, string localDirectory, params string[] commands)
    {
        return await RunAsync(server, localDirectory, DefaultExitGracePeriod, commands);
    }

    public static Task<Result> RunAsync(SftpServerFixture server, string localDirectory, TimeSpan exitGracePeriod, params string[] commands)
    {
        return RunAsync(server, localDirectory, exitGracePeriod, Array.Empty<string>(), commands);
    }

    /// <summary>
    /// Like <see cref="RunAsync(SftpServerFixture, string, string[])"/>, with extra ssh options such as
    /// "HostKeyAlgorithms=ssh-rsa" or "LogLevel=DEBUG". They come before the default options, so they win
    /// (ssh uses the first value of an option).
    /// </summary>
    public static Task<Result> RunWithOptionsAsync(SftpServerFixture server, string localDirectory, string[] sshOptions, params string[] commands)
    {
        return RunAsync(server, localDirectory, DefaultExitGracePeriod, sshOptions.SelectMany(o => new[] { "-o", o }).ToArray(), commands);
    }

    /// <summary>
    /// Like <see cref="RunAsync(SftpServerFixture, string, string[])"/>, with extra sftp command line
    /// arguments such as "-R", "256" (number of requests in flight) or "-B", "32768" (request size), and
    /// another port than the server port (for example a proxy in front of the server).
    /// </summary>
    public static Task<Result> RunWithArgumentsAsync(SftpServerFixture server, string localDirectory, int port, string[] sftpArguments, params string[] commands)
    {
        return RunAsync(server, localDirectory, DefaultExitGracePeriod, sftpArguments, commands, port);
    }

    private static async Task<Result> RunAsync(SftpServerFixture server, string localDirectory, TimeSpan exitGracePeriod, string[] extraArguments, string[] commands, int? port = null)
    {
        var askPass = CreateAskPassScript(server);

        var startInfo = new ProcessStartInfo(SftpPath.Value ?? "sftp")
        {
            WorkingDirectory = localDirectory,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        foreach (var argument in extraArguments)
            startInfo.ArgumentList.Add(argument);

        foreach (var argument in new[]
                 {
                     "-F", "none", // do not read the user's ~/.ssh/config
                     "-P", (port ?? server.Port).ToString(),
                     "-o", "StrictHostKeyChecking=no",
                     "-o", "UserKnownHostsFile=" + (OperatingSystem.IsWindows() ? "NUL" : "/dev/null"),
                     "-o", "PreferredAuthentications=password",
                     "-o", "PubkeyAuthentication=no",
                     "-o", "NumberOfPasswordPrompts=1",
                     "-o", "ConnectTimeout=15",
                     // Set FREESFTPSHARP_SFTP_LOGLEVEL=DEBUG3 to see the ssh protocol log in a failing test.
                     "-o", "LogLevel=" + (Environment.GetEnvironmentVariable("FREESFTPSHARP_SFTP_LOGLEVEL") ?? "ERROR"),
                     $"{server.Username}@{SftpServerFixture.Host}",
                 })
        {
            startInfo.ArgumentList.Add(argument);
        }

        startInfo.Environment["SSH_ASKPASS"] = askPass;
        startInfo.Environment["SSH_ASKPASS_REQUIRE"] = "force";
        startInfo.Environment["DISPLAY"] = ":0";
        startInfo.Environment.Remove("SSH_AUTH_SOCK");

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start sftp.");

        var stdout = new StringBuilder();
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stdoutTask = Task.Run(async () =>
        {
            string? line;
            while ((line = await process.StandardOutput.ReadLineAsync()) != null)
            {
                lock (stdout)
                    stdout.AppendLine(line);
                if (line.StartsWith(DoneMarker, StringComparison.Ordinal))
                    done.TrySetResult();
            }
        });
        var stderrTask = process.StandardError.ReadToEndAsync();

        var input = new StringBuilder();
        foreach (var command in commands)
            input.Append(command).Append('\n');
        input.Append("lpwd\n");
        await process.StandardInput.WriteAsync(input.ToString());
        process.StandardInput.Close();

        var timeout = TimeSpan.FromSeconds(60);
        var exited = process.WaitForExitAsync();
        var first = await Task.WhenAny(exited, done.Task, Task.Delay(timeout));
        if (first == done.Task)
            await Task.WhenAny(exited, Task.Delay(exitGracePeriod));

        var exitedByItself = process.HasExited;
        if (!exitedByItself)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            await process.WaitForExitAsync();
        }

        await Task.WhenAny(Task.WhenAll(stdoutTask, stderrTask), Task.Delay(TimeSpan.FromSeconds(5)));
        string output;
        lock (stdout)
            output = stdout.ToString();
        var errors = stderrTask.IsCompletedSuccessfully ? stderrTask.Result : string.Empty;

        if (first != done.Task && !exitedByItself)
            throw new TimeoutException($"sftp did not finish the commands within {timeout}.{Environment.NewLine}{output}{Environment.NewLine}{errors}");

        return new Result(exitedByItself, exitedByItself ? process.ExitCode : null, output, errors);
    }

    /// <summary>Quotes a local or remote path for an sftp command line.</summary>
    public static string Quote(string path) => "\"" + path.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    private static string CreateAskPassScript(SftpServerFixture server)
    {
        if (OperatingSystem.IsWindows())
        {
            var cmdPath = Path.Combine(server.TempDirectory, "askpass.cmd");
            if (!File.Exists(cmdPath))
                File.WriteAllText(cmdPath, "@echo " + server.Password + "\r\n");
            return cmdPath;
        }

        var shPath = Path.Combine(server.TempDirectory, "askpass.sh");
        if (!File.Exists(shPath))
        {
            File.WriteAllText(shPath, "#!/bin/sh\necho '" + server.Password + "'\n");
            File.SetUnixFileMode(shPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        return shPath;
    }

    private static string? FindSftpOnPath()
    {
        var names = OperatingSystem.IsWindows() ? new[] { "sftp.exe" } : new[] { "sftp" };
        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var name in names)
            {
                var candidate = Path.Combine(directory.Trim('"'), name);
                if (File.Exists(candidate))
                    return candidate;
            }
        }
        return null;
    }
}
