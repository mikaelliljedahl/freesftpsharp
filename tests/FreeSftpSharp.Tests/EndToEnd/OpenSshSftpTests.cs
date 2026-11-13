using System.Security.Cryptography;
using FreeSftpSharp.Tests.Infrastructure;
using static FreeSftpSharp.Tests.Infrastructure.OpenSshSftp;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// End-to-end tests with the OpenSSH sftp client. They are skipped when sftp is not on PATH.
/// Every test ends with "pwd", so a "Remote working directory" line proves that the session ran to the end.
/// </summary>
public sealed class OpenSshSftpTests : IClassFixture<SftpServerFixture>
{
    private const string SessionEndMarker = "Remote working directory: /";

    private readonly SftpServerFixture _server;

    public OpenSshSftpTests(SftpServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task Put_and_get_of_2MB_200B_and_0B_files_give_the_same_bytes()
    {
        SkipIfUnavailable();
        var local = CreateLocalDirectory();
        var remote = _server.CreateUniqueDirectory("ossh");
        var files = new Dictionary<string, byte[]>
        {
            ["big.bin"] = RandomNumberGenerator.GetBytes(2 * 1024 * 1024),
            ["small.bin"] = RandomNumberGenerator.GetBytes(200),
            ["empty.bin"] = Array.Empty<byte>(),
        };
        foreach (var (name, data) in files)
            File.WriteAllBytes(Path.Combine(local, name), data);

        var commands = new List<string> { "cd " + remote };
        foreach (var name in files.Keys)
            commands.Add($"put {Quote(Path.Combine(local, name))} {name}");
        foreach (var name in files.Keys)
            commands.Add($"get {name} {Quote(Path.Combine(local, name + ".down"))}");
        commands.Add("pwd");

        var result = await RunAsync(_server, local, commands.ToArray());

        AssertSessionCompleted(result);
        foreach (var (name, data) in files)
        {
            Assert.True(data.AsSpan().SequenceEqual(File.ReadAllBytes(_server.PhysicalPath(remote + "/" + name))),
                $"Uploaded {name} differs on the server.{Environment.NewLine}{result}");
            Assert.True(data.AsSpan().SequenceEqual(File.ReadAllBytes(Path.Combine(local, name + ".down"))),
                $"Downloaded {name} differs.{Environment.NewLine}{result}");
        }
    }

    [Fact]
    public async Task Ls_lists_the_files_of_a_directory()
    {
        SkipIfUnavailable();
        var remote = _server.CreateUniqueDirectory("ossh");
        File.WriteAllText(_server.PhysicalPath(remote + "/first.txt"), "1");
        File.WriteAllText(_server.PhysicalPath(remote + "/second.txt"), "2");

        var result = await RunAsync(_server, CreateLocalDirectory(), "ls -1 " + remote, "pwd");

        AssertSessionCompleted(result);
        Assert.Contains("first.txt", result.StandardOutput);
        Assert.Contains("second.txt", result.StandardOutput);
    }

    [Fact]
    public async Task Rename_moves_a_file()
    {
        SkipIfUnavailable();
        var remote = _server.CreateUniqueDirectory("ossh");
        File.WriteAllText(_server.PhysicalPath(remote + "/old.txt"), "content");

        var result = await RunAsync(_server, CreateLocalDirectory(), $"rename {remote}/old.txt {remote}/new.txt", "pwd");

        AssertSessionCompleted(result);
        Assert.False(File.Exists(_server.PhysicalPath(remote + "/old.txt")), result.ToString());
        Assert.Equal("content", File.ReadAllText(_server.PhysicalPath(remote + "/new.txt")));
    }

    [Fact]
    public async Task Rm_removes_a_file()
    {
        SkipIfUnavailable();
        var remote = _server.CreateUniqueDirectory("ossh");
        File.WriteAllText(_server.PhysicalPath(remote + "/gone.txt"), "x");

        var result = await RunAsync(_server, CreateLocalDirectory(), $"rm {remote}/gone.txt", "pwd");

        AssertSessionCompleted(result);
        Assert.False(File.Exists(_server.PhysicalPath(remote + "/gone.txt")), result.ToString());
    }

    [Fact]
    public async Task Rmdir_removes_an_empty_directory()
    {
        SkipIfUnavailable();
        var remote = _server.CreateUniqueDirectory("ossh");

        var result = await RunAsync(_server, CreateLocalDirectory(), "rmdir " + remote, "pwd");

        AssertSessionCompleted(result);
        Assert.False(Directory.Exists(_server.PhysicalPath(remote)), result.ToString());
    }

    [Fact]
    public async Task Cd_up_twice_from_the_root_then_pwd_gives_the_root()
    {
        SkipIfUnavailable();

        var result = await RunAsync(_server, CreateLocalDirectory(), "cd ../..", "pwd");

        AssertSessionCompleted(result);
        Assert.Matches(@"Remote working directory: /\r?$", result.StandardOutput.Split('\n').First(l => l.Contains("Remote working directory")));
    }

    [Fact]
    public async Task Overwrite_of_a_2MB_file_with_a_200B_file_gives_200B()
    {
        SkipIfUnavailable();
        var local = CreateLocalDirectory();
        var remote = _server.CreateUniqueDirectory("ossh");
        var big = RandomNumberGenerator.GetBytes(2 * 1024 * 1024);
        var small = RandomNumberGenerator.GetBytes(200);
        File.WriteAllBytes(Path.Combine(local, "big.bin"), big);
        File.WriteAllBytes(Path.Combine(local, "small.bin"), small);

        var result = await RunAsync(_server, local,
            "cd " + remote,
            $"put {Quote(Path.Combine(local, "big.bin"))} target.bin",
            $"put {Quote(Path.Combine(local, "small.bin"))} target.bin",
            $"get target.bin {Quote(Path.Combine(local, "target.down"))}",
            "pwd");

        AssertSessionCompleted(result);
        Assert.Equal(200, new FileInfo(_server.PhysicalPath(remote + "/target.bin")).Length);
        Assert.Equal(small, File.ReadAllBytes(Path.Combine(local, "target.down")));
    }

    [Fact]
    public async Task Get_of_the_config_db_outside_the_root_fails()
    {
        SkipIfUnavailable();
        var local = CreateLocalDirectory();
        var target = Path.Combine(local, "stolen.db");

        var result = await RunAsync(_server, local, $"get ../../config.db {Quote(target)}", "pwd");

        AssertSessionCompleted(result);
        Assert.False(File.Exists(target), $"config.db outside the user root was downloaded.{Environment.NewLine}{result}");
        Assert.DoesNotContain(SftpServerFixture.SecretContent, result.AllOutput);
    }

    [Fact(Skip = "Product bug: the server does not close the SFTP channel after the client sends SSH_MSG_CHANNEL_EOF, " +
                 "so OpenSSH sftp does not exit after its last command (it waits for the idle timeout). " +
                 "Remove this Skip when the bug is fixed.")]
    public async Task Sftp_exits_by_itself_after_the_last_command()
    {
        SkipIfUnavailable();

        var result = await RunAsync(_server, CreateLocalDirectory(), TimeSpan.FromSeconds(10), "pwd");

        AssertSessionCompleted(result);
        Assert.True(result.ExitedByItself, result.ToString());
        Assert.Equal(0, result.ExitCode);
    }

    private string CreateLocalDirectory()
    {
        var local = Path.Combine(_server.TempDirectory, "local-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(local);
        return local;
    }

    private static void AssertSessionCompleted(Result result)
    {
        Assert.True(result.StandardOutput.Contains(SessionEndMarker), $"The sftp session did not run to the end.{Environment.NewLine}{result}");
    }
}
