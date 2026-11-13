using System.Text;
using FxSsh.Services.Sftp;
using SshServer.Interfaces;
using static FreeSftpSharp.Tests.Sftp.SftpEngineClient;

namespace FreeSftpSharp.Tests.Sftp;

/// <summary>
/// The user root is the security boundary: no SFTP request can read, write, list, remove or rename
/// anything outside it, and no status message shows the physical path of the root.
/// </summary>
public sealed class SftpPathTraversalTests : SftpEngineTestBase
{
    [Theory]
    [InlineData("/../config.db")]
    [InlineData("../../config.db")]
    [InlineData("..\\config.db")]
    [InlineData("/a/../../config.db")]
    public void File_outside_the_root_cannot_be_opened_stat_removed_or_renamed(string path)
    {
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Open(path, SftpOpenFlags.Read).StatusCode);
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Status(SSH_FXP_STAT, path));
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Status(SSH_FXP_REMOVE, path));
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Rename(path, "/stolen.db"));

        Assert.Equal(SecretContent, File.ReadAllText(SecretFilePath));
        Assert.False(File.Exists(Physical("/stolen.db")));
    }

    [Fact]
    public void Write_to_a_parent_path_lands_inside_the_root()
    {
        var handle = Client.OpenHandle("/../config.db", SftpOpenFlags.Write | SftpOpenFlags.Create | SftpOpenFlags.Truncate);
        Assert.Equal(SSH_FX_OK, Client.Write(handle, 0, Encoding.ASCII.GetBytes("x")));
        Assert.Equal(SSH_FX_OK, Client.Close(handle));

        Assert.Equal("x", File.ReadAllText(Physical("/config.db")));
        Assert.Equal(SecretContent, File.ReadAllText(SecretFilePath));
    }

    [Fact]
    public void Rename_to_a_parent_path_lands_inside_the_root()
    {
        Directory.CreateDirectory(Physical("/dir"));
        File.WriteAllText(Physical("/dir/a.txt"), "a");

        Assert.Equal(SSH_FX_OK, Client.Rename("/dir/a.txt", "/dir/../../../a.txt"));

        Assert.True(File.Exists(Physical("/a.txt")));
        Assert.False(File.Exists(Path.Combine(TempDirectory, "a.txt")));
    }

    [Fact]
    public void Listing_of_the_parent_of_the_root_lists_the_root()
    {
        File.WriteAllText(Physical("/marker.txt"), "m");

        var parent = Client.ReadDirectory("/..").Select(e => e.Name).Order(StringComparer.Ordinal).ToList();
        var root = Client.ReadDirectory("/").Select(e => e.Name).Order(StringComparer.Ordinal).ToList();

        Assert.Equal(root, parent);
        Assert.Contains("marker.txt", parent);
        Assert.DoesNotContain("config.db", parent);
        Assert.DoesNotContain("root", parent);
    }

    [Fact]
    public void Mkdir_and_setstat_of_a_parent_path_stay_inside_the_root()
    {
        Assert.Equal(SSH_FX_OK, Client.MakeDirectory("/../../newdir"));
        Assert.Equal(SSH_FX_OK, Client.SetStat("/..", new SftpFileAttributes { AccessTime = 1, ModificationTime = 1 }));

        Assert.True(Directory.Exists(Physical("/newdir")));
        Assert.False(Directory.Exists(Path.Combine(TempDirectory, "newdir")));
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1).UtcDateTime, Directory.GetLastWriteTimeUtc(Root));
        Assert.NotEqual(DateTimeOffset.FromUnixTimeSeconds(1).UtcDateTime, Directory.GetLastWriteTimeUtc(TempDirectory));
    }

    [Fact]
    public void Status_messages_do_not_contain_the_physical_path()
    {
        Directory.CreateDirectory(Physical("/dir"));
        File.WriteAllText(Physical("/dir/a.txt"), "a");
        File.WriteAllText(Physical("/b.txt"), "b");

        var responses = new[]
        {
            Client.Open("/missing.txt", SftpOpenFlags.Read),
            Client.Open("/missing/new.txt", SftpOpenFlags.Write | SftpOpenFlags.Create),
            Client.Open("/dir", SftpOpenFlags.Read),
            Client.Open("/b.txt", SftpOpenFlags.Write | SftpOpenFlags.Create | SftpOpenFlags.Exclusive),
            Client.SendPath(SSH_FXP_STAT, "/missing"),
            Client.SendPath(SSH_FXP_OPENDIR, "/missing"),
            Client.SendPath(SSH_FXP_RMDIR, "/dir"),
            Client.SendPath(SSH_FXP_REMOVE, "/missing"),
        };

        foreach (var response in responses)
        {
            Assert.NotEqual(SSH_FX_OK, response.StatusCode);
            Assert.DoesNotContain(TempDirectory, response.StatusMessage);
            Assert.DoesNotContain("freesftpsharp-tests", response.StatusMessage);
        }
    }

    [Fact]
    public void Access_denied_by_the_file_system_gives_permission_denied_without_the_physical_path()
    {
        using var client = new SftpEngineClient(new DenyingFileSystem());
        client.Service.OnData(Init());

        var responses = new[]
        {
            client.Open("/a.txt", SftpOpenFlags.Read),
            client.SendPath(SSH_FXP_STAT, "/a.txt"),
            client.SendPath(SSH_FXP_OPENDIR, "/"),
            client.SendPath(SSH_FXP_REMOVE, "/a.txt"),
            client.SendPath(SSH_FXP_RMDIR, "/dir"),
        };

        foreach (var response in responses)
        {
            Assert.Equal(SSH_FX_PERMISSION_DENIED, response.StatusCode);
            Assert.DoesNotContain(DenyingFileSystem.PhysicalPath, response.StatusMessage);
        }
    }

    /// <summary>A file system that denies everything, like <c>LocalFileSystem.GetPhysicalPath</c> for a path outside the root.</summary>
    private sealed class DenyingFileSystem : IFileSystem
    {
        public const string PhysicalPath = "/srv/secret/physical/root";

        private static UnauthorizedAccessException Denied() => new($"Access to the path '{PhysicalPath}' is denied.");

        public bool RemoveDirectory(string pathToRemove) => throw Denied();
        public bool MakeDirectory(string newPath) => throw Denied();
        public bool DirectoryExists(string path) => throw Denied();
        public bool FileExists(string path) => throw Denied();
        public Stream OpenStreamRead(string path) => throw Denied();
        public Stream OpenStreamWrite(string path) => throw Denied();
        public Stream OpenStreamWrite(string path, FileMode mode) => throw Denied();
        public IEnumerable<Resource> GetFiles(string path) => throw Denied();
        public IEnumerable<Resource> GetDirectories(string path) => throw Denied();
        public bool RemoveFile(string path) => throw Denied();
        public ulong GetSize(string path) => throw Denied();
        public DateTime GetDirectoryLastModified(string path) => throw Denied();
        public DateTime GetDirectoryLastAccessed(string path) => throw Denied();
        public DateTime GetFileLastModified(string path) => throw Denied();
        public DateTime GetFileLastAccessed(string path) => throw Denied();
        public bool MoveFileOrDirectory(string oldpath, string newpath) => throw Denied();
        public FileSystemEntryInfo? GetInfo(string path) => throw Denied();
        public Stream OpenFile(string path, FileMode mode, FileAccess access) => throw Denied();
        public void SetFileLength(string path, long length) => throw Denied();
        public void SetTimes(string path, DateTime? lastAccessUtc, DateTime? lastWriteUtc) => throw Denied();
        public void SetPermissions(string path, uint mode) => throw Denied();
    }
}
