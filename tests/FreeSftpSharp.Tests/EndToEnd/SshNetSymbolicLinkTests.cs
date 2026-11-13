using System.Text;
using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet.Common;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// A link inside the user root to the directory with the secret file (config.db) next to the root gives
/// permission denied over SSH (issue #25), and a client cannot create a link.
/// </summary>
public sealed class SshNetSymbolicLinkTests : IClassFixture<SftpServerFixture>
{
    private readonly SftpServerFixture _server;

    public SshNetSymbolicLinkTests(SftpServerFixture server)
    {
        _server = server;
    }

    /// <summary>Creates a link in a new directory of the user root to the parent of the root and returns its virtual path.</summary>
    private string CreateLinkToOutside()
    {
        var directory = _server.CreateUniqueDirectory("links");
        var link = directory + "/out";
        FileLinks.CreateDirectoryLink(_server.PhysicalPath(link), _server.TempDirectory);
        return link;
    }

    [Fact]
    public void File_behind_a_link_to_outside_the_root_cannot_be_read()
    {
        var link = CreateLinkToOutside();
        using var client = _server.Connect();

        Assert.Throws<SftpPermissionDeniedException>(() =>
        {
            using var stream = new MemoryStream();
            client.DownloadFile(link + "/config.db", stream);
        });
    }

    [Fact]
    public void Link_to_outside_the_root_cannot_be_listed_written_or_changed()
    {
        var link = CreateLinkToOutside();
        using var client = _server.Connect();

        Assert.Throws<SftpPermissionDeniedException>(() => client.ListDirectory(link).ToList());
        Assert.Throws<SftpPermissionDeniedException>(() => client.GetAttributes(link + "/config.db"));
        Assert.Throws<SftpPermissionDeniedException>(() =>
        {
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes("x"));
            client.UploadFile(stream, link + "/config.db");
        });
        Assert.Throws<SftpPermissionDeniedException>(() => client.CreateDirectory(link + "/newdir"));
        Assert.Throws<SftpPermissionDeniedException>(() => client.DeleteFile(link + "/config.db"));
        Assert.Throws<SftpPermissionDeniedException>(() => client.RenameFile(link + "/config.db", "/stolen.db"));

        Assert.Equal(SftpServerFixture.SecretContent, File.ReadAllText(_server.SecretFilePath));
        Assert.False(Directory.Exists(Path.Combine(_server.TempDirectory, "newdir")));
        Assert.False(File.Exists(_server.PhysicalPath("/stolen.db")));
    }

    [Fact]
    public void Listing_of_the_directory_with_the_link_does_not_show_it()
    {
        var link = CreateLinkToOutside();
        var directory = link[..link.LastIndexOf('/')];
        using var client = _server.Connect();

        var names = client.ListDirectory(directory).Select(f => f.Name).ToList();

        Assert.DoesNotContain("out", names);
    }

    [Fact]
    public void Client_cannot_create_a_symbolic_link()
    {
        var directory = _server.CreateUniqueDirectory("symlink");
        using var client = _server.Connect();

        Assert.ThrowsAny<SshException>(() => client.SymbolicLink("/..", directory + "/escape"));

        Assert.False(Path.Exists(_server.PhysicalPath(directory + "/escape")));
    }
}
