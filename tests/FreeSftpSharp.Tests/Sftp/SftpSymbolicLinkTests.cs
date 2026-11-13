using System.Text;
using FreeSftpSharp.Tests.Infrastructure;
using FxSsh.Services.Sftp;
using static FreeSftpSharp.Tests.Sftp.SftpEngineClient;

namespace FreeSftpSharp.Tests.Sftp;

/// <summary>
/// SFTP requests through a link inside the user root to the directory with the secret file next to the
/// root give SSH_FX_PERMISSION_DENIED (issue #25). Clients cannot create or read links:
/// SSH_FXP_SYMLINK and SSH_FXP_READLINK give SSH_FX_OP_UNSUPPORTED (see SftpFileOperationTests).
/// </summary>
public sealed class SftpSymbolicLinkTests : SftpEngineTestBase
{
    public SftpSymbolicLinkTests()
    {
        FileLinks.CreateDirectoryLink(Physical("/out"), TempDirectory);
    }

    [Fact]
    public void Requests_through_a_link_to_outside_the_root_are_denied()
    {
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.Open("/out/config.db", SftpOpenFlags.Read).StatusCode);
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.Open("/out/new.txt", SftpOpenFlags.Write | SftpOpenFlags.Create).StatusCode);
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.Status(SSH_FXP_STAT, "/out/config.db"));
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.Status(SSH_FXP_LSTAT, "/out"));
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.Status(SSH_FXP_OPENDIR, "/out"));
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.Status(SSH_FXP_REMOVE, "/out/config.db"));
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.Status(SSH_FXP_RMDIR, "/out/root"));
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.MakeDirectory("/out/newdir"));
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.SetStat("/out/config.db", new SftpFileAttributes { Size = 0 }));
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.Rename("/out/config.db", "/stolen.db"));
        File.WriteAllText(Physical("/mine.txt"), "mine");
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.Rename("/mine.txt", "/out/mine.txt"));

        Assert.Equal(SecretContent, File.ReadAllText(SecretFilePath));
        Assert.False(File.Exists(Path.Combine(TempDirectory, "new.txt")));
        Assert.False(Directory.Exists(Path.Combine(TempDirectory, "newdir")));
        Assert.False(File.Exists(Path.Combine(TempDirectory, "mine.txt")));
        Assert.False(File.Exists(Physical("/stolen.db")));
    }

    [Fact]
    public void Listing_of_the_root_hides_a_link_to_outside_the_root()
    {
        File.WriteAllText(Physical("/marker.txt"), "m");

        var names = Client.ReadDirectory("/").Select(e => e.Name).ToList();

        Assert.Contains("marker.txt", names);
        Assert.DoesNotContain("out", names);
    }

    [Fact]
    public void Status_message_of_a_denied_link_has_no_physical_path()
    {
        var response = Client.Open("/out/config.db", SftpOpenFlags.Read);

        Assert.Equal(SSH_FX_PERMISSION_DENIED, response.StatusCode);
        Assert.DoesNotContain(TempDirectory, response.ToString());
    }

    [Fact]
    public void Link_to_a_directory_inside_the_root_keeps_working()
    {
        Directory.CreateDirectory(Physical("/real"));
        FileLinks.CreateDirectoryLink(Physical("/alias"), Physical("/real"));

        var handle = Client.OpenHandle("/alias/a.txt", SftpOpenFlags.Write | SftpOpenFlags.Create);
        Assert.Equal(SSH_FX_OK, Client.Write(handle, 0, Encoding.ASCII.GetBytes("a")));
        Assert.Equal(SSH_FX_OK, Client.Close(handle));

        Assert.Equal("a", File.ReadAllText(Physical("/real/a.txt")));
        Assert.Contains("a.txt", Client.ReadDirectory("/alias").Select(e => e.Name));
    }
}
