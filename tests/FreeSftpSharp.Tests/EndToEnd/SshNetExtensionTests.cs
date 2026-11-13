using System.Text;
using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet.Common;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// The OpenSSH SFTP extensions with SSH.NET: it uses posix-rename@openssh.com and statvfs@openssh.com
/// only when the server announces them (otherwise it throws <see cref="NotSupportedException"/>).
/// </summary>
public sealed class SshNetExtensionTests : IClassFixture<SftpServerFixture>
{
    private readonly SftpServerFixture _server;

    public SshNetExtensionTests(SftpServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public void Posix_rename_replaces_an_existing_file()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();
        File.WriteAllText(_server.PhysicalPath(dir + "/new.txt"), "new content");
        File.WriteAllText(_server.PhysicalPath(dir + "/current.txt"), "old content");

        client.RenameFile(dir + "/new.txt", dir + "/current.txt", isPosix: true);

        Assert.False(File.Exists(_server.PhysicalPath(dir + "/new.txt")));
        Assert.Equal("new content", File.ReadAllText(_server.PhysicalPath(dir + "/current.txt")));
    }

    [Fact]
    public void Plain_rename_onto_an_existing_file_still_fails()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();
        File.WriteAllText(_server.PhysicalPath(dir + "/new.txt"), "new content");
        File.WriteAllText(_server.PhysicalPath(dir + "/current.txt"), "old content");

        Assert.ThrowsAny<SshException>(() => client.RenameFile(dir + "/new.txt", dir + "/current.txt"));

        Assert.Equal("old content", File.ReadAllText(_server.PhysicalPath(dir + "/current.txt")));
    }

    [Fact]
    public void Posix_rename_of_a_file_outside_the_root_fails()
    {
        using var client = _server.Connect();

        Assert.Throws<SftpPathNotFoundException>(() => client.RenameFile("/../config.db", "/stolen.db", isPosix: true));

        Assert.Equal(SftpServerFixture.SecretContent, File.ReadAllText(_server.SecretFilePath));
        Assert.False(File.Exists(_server.PhysicalPath("/stolen.db")));
    }

    [Fact]
    public void GetStatus_gives_the_disk_space_with_statvfs()
    {
        using var client = _server.Connect();

        var status = client.GetStatus("/");

        var drive = new DriveInfo(OperatingSystem.IsWindows() ? Path.GetPathRoot(_server.UserRoot)! : _server.UserRoot);
        Assert.True(status.FileSystemBlockSize > 0);
        Assert.Equal((ulong)drive.TotalSize / status.FileSystemBlockSize, status.TotalBlocks);
        Assert.InRange(status.AvailableBlocks, 0ul, status.TotalBlocks);
        Assert.False(status.IsReadOnly);
    }

    [Fact]
    public void GetStatus_of_a_missing_path_fails()
    {
        using var client = _server.Connect();

        Assert.Throws<SftpPathNotFoundException>(() => client.GetStatus("/missing-" + Guid.NewGuid().ToString("N")));
    }

    [Fact]
    public void Upload_and_download_after_the_extension_handshake_give_the_same_bytes()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();
        var data = Encoding.ASCII.GetBytes(new string('x', 200 * 1024 + 5));

        using (var upload = new MemoryStream(data))
            client.UploadFile(upload, dir + "/file.bin");
        using var download = new MemoryStream();
        client.DownloadFile(dir + "/file.bin", download);

        Assert.Equal(data, download.ToArray());
    }
}
