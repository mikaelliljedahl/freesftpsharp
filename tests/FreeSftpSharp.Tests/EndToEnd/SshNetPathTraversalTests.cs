using System.Text;
using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet.Common;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// The fixture puts a secret file (config.db) next to the user root. No client path may reach it.
/// </summary>
public sealed class SshNetPathTraversalTests : IClassFixture<SftpServerFixture>
{
    private readonly SftpServerFixture _server;

    public SshNetPathTraversalTests(SftpServerFixture server)
    {
        _server = server;
    }

    [Theory]
    [InlineData("/../config.db")]
    [InlineData("/../../config.db")]
    [InlineData("../config.db")]
    public void File_outside_the_root_cannot_be_read(string path)
    {
        using var client = _server.Connect();

        Assert.Throws<SftpPathNotFoundException>(() =>
        {
            using var stream = new MemoryStream();
            client.DownloadFile(path, stream);
        });
    }

    [Fact]
    public void Upload_to_a_parent_path_lands_inside_the_root()
    {
        using var client = _server.Connect();
        var name = $"evil-{Guid.NewGuid():N}.txt";

        using (var stream = new MemoryStream(Encoding.UTF8.GetBytes("x")))
            client.UploadFile(stream, "/../" + name);

        Assert.True(File.Exists(Path.Combine(_server.UserRoot, name)), "The file must be written inside the user root.");
        Assert.False(File.Exists(Path.Combine(_server.TempDirectory, name)), "The file must not be written in the parent directory.");
        Assert.Equal(SftpServerFixture.SecretContent, File.ReadAllText(_server.SecretFilePath));
    }

    [Fact]
    public void ListDirectory_of_parent_lists_the_root()
    {
        using var client = _server.Connect();
        var marker = _server.CreateUniqueDirectory("marker").TrimStart('/');

        var parentNames = client.ListDirectory("/..").Select(f => f.Name).ToList();
        var rootNames = client.ListDirectory("/").Select(f => f.Name).ToList();

        Assert.Contains(marker, parentNames);
        Assert.DoesNotContain("config.db", parentNames);
        Assert.DoesNotContain("root", parentNames);
        Assert.Equal(rootNames.OrderBy(n => n), parentNames.OrderBy(n => n));
    }

    [Fact]
    public void Exists_is_false_for_the_file_outside_the_root()
    {
        using var client = _server.Connect();

        Assert.False(client.Exists("/../config.db"));
    }
}
