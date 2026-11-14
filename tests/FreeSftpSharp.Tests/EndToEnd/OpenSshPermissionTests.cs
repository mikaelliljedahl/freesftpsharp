using FreeSftpSharp.Tests.Infrastructure;
using SshServer.Interfaces;
using SshServer.Interfaces.Permissions;
using static FreeSftpSharp.Tests.Infrastructure.OpenSshSftp;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// Per-path permissions and path filters (issue #59) with the OpenSSH sftp client, through the real server and the
/// local disk. The test user has "/ = All", "/incoming = Upload", "/incoming/sub = All", denies "*.exe" and hides
/// "*.secret". Each check runs in its own sftp session, so an error line belongs to one command.
/// </summary>
public sealed class OpenSshPermissionTests : IClassFixture<OpenSshPermissionTests.PermissionFixture>
{
    private const string SessionEndMarker = "Remote working directory: /";

    private readonly PermissionFixture _server;

    public OpenSshPermissionTests(PermissionFixture server)
    {
        _server = server;
    }

    public sealed class PermissionFixture : SftpServerFixture
    {
        protected override void ConfigureUser(User user)
        {
            user.Permissions = new()
            {
                ["/"] = FilePermissions.All,
                ["/incoming"] = FilePermissions.Upload,
                ["/incoming/sub"] = FilePermissions.All,
            };
            user.PathFilters = new()
            {
                ["/"] = new PathFilter { DeniedPatterns = ["*.exe"], HiddenPatterns = ["*.secret"] },
            };
        }

        public PermissionFixture()
        {
            Directory.CreateDirectory(PhysicalPath("/incoming/sub"));
            File.WriteAllText(PhysicalPath("/incoming/existing.txt"), "existing");
            File.WriteAllText(PhysicalPath("/incoming/sub/inside.txt"), "inside");
            File.WriteAllText(PhysicalPath("/visible.txt"), "visible");
            File.WriteAllText(PhysicalPath("/key.secret"), "secret");
        }
    }

    [Fact]
    public async Task Upload_only_directory_accepts_a_new_file()
    {
        SkipIfUnavailable();
        var local = LocalFile("new.txt", "new");

        var result = await RunAsync(_server, Path.GetDirectoryName(local)!, $"put {Quote(local)} /incoming/new-{Guid.NewGuid():N}.txt", "pwd");

        AssertSessionCompleted(result);
        Assert.DoesNotContain("denied", result.AllOutput, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(Directory.GetFiles(_server.PhysicalPath("/incoming"), "new-*.txt"), f => File.ReadAllText(f) == "new");
    }

    [Theory]
    [InlineData("ls /incoming")]
    [InlineData("get /incoming/existing.txt")]
    [InlineData("put {local} /incoming/existing.txt")]
    [InlineData("rm /incoming/existing.txt")]
    [InlineData("rename /incoming/existing.txt /incoming/renamed.txt")]
    [InlineData("mkdir /incoming/dir")]
    public async Task Upload_only_directory_denies_everything_else(string command)
    {
        SkipIfUnavailable();
        var local = LocalFile("overwrite.txt", "overwritten");

        var result = await RunAsync(_server, Path.GetDirectoryName(local)!, command.Replace("{local}", Quote(local)), "pwd");

        AssertSessionCompleted(result);
        Assert.True(result.AllOutput.Contains("Permission denied"), result.ToString());
        Assert.Equal("existing", File.ReadAllText(_server.PhysicalPath("/incoming/existing.txt")));
        Assert.False(File.Exists(_server.PhysicalPath("/incoming/renamed.txt")));
        Assert.False(Directory.Exists(_server.PhysicalPath("/incoming/dir")));
        Assert.False(File.Exists(Path.Combine(Path.GetDirectoryName(local)!, "existing.txt")));
    }

    [Fact]
    public async Task A_more_specific_directory_overrides_upload_only()
    {
        SkipIfUnavailable();
        var local = LocalFile("sub.txt", "sub");
        var name = $"sub-{Guid.NewGuid():N}.txt";

        var result = await RunAsync(_server, Path.GetDirectoryName(local)!,
            $"put {Quote(local)} /incoming/sub/{name}",
            $"put {Quote(local)} /incoming/sub/{name}",
            "ls -1 /incoming/sub",
            $"get /incoming/sub/inside.txt {Quote(local + ".down")}",
            $"rm /incoming/sub/{name}",
            "pwd");

        AssertSessionCompleted(result);
        Assert.DoesNotContain("denied", result.AllOutput, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("inside.txt", result.StandardOutput);
        Assert.Equal("inside", File.ReadAllText(local + ".down"));
        Assert.False(File.Exists(_server.PhysicalPath("/incoming/sub/" + name)));
    }

    [Theory]
    [InlineData("put {local} /setup.exe")]
    [InlineData("rename /visible.txt /visible.exe")]
    public async Task A_denied_pattern_cannot_be_uploaded_or_renamed_to(string command)
    {
        SkipIfUnavailable();
        var local = LocalFile("setup.exe", "binary");

        var result = await RunAsync(_server, Path.GetDirectoryName(local)!, command.Replace("{local}", Quote(local)), "pwd");

        AssertSessionCompleted(result);
        Assert.Contains("Permission denied", result.AllOutput);
        Assert.False(File.Exists(_server.PhysicalPath("/setup.exe")));
        Assert.False(File.Exists(_server.PhysicalPath("/visible.exe")));
        Assert.True(File.Exists(_server.PhysicalPath("/visible.txt")));
    }

    [Fact]
    public async Task A_hidden_pattern_is_not_listed_and_gives_no_such_file()
    {
        SkipIfUnavailable();
        var local = LocalDirectory();

        var listing = await RunAsync(_server, local, "ls -1 /", "pwd");
        var stat = await RunAsync(_server, local, "ls -l /key.secret", "pwd");
        var get = await RunAsync(_server, local, "get /key.secret", "pwd");

        AssertSessionCompleted(listing);
        Assert.Contains("visible.txt", listing.StandardOutput);
        Assert.DoesNotContain("key.secret", listing.StandardOutput);
        AssertSessionCompleted(stat);
        Assert.Contains("not found", stat.AllOutput);
        AssertSessionCompleted(get);
        Assert.Contains("not found", get.AllOutput, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(Path.Combine(local, "key.secret")));
    }

    private string LocalDirectory()
    {
        var local = Path.Combine(_server.TempDirectory, "local-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(local);
        return local;
    }

    private string LocalFile(string name, string content)
    {
        var path = Path.Combine(LocalDirectory(), name);
        File.WriteAllText(path, content);
        return path;
    }

    private static void AssertSessionCompleted(Result result)
    {
        Assert.True(result.StandardOutput.Contains(SessionEndMarker), $"The sftp session did not run to the end.{Environment.NewLine}{result}");
    }
}
