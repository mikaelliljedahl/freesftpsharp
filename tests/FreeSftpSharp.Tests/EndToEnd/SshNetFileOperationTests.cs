using System.Security.Cryptography;
using System.Text;
using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// File operations with SSH.NET against the in-process server. Every test works in its own directory,
/// so the tests do not depend on each other or on their order.
/// </summary>
public sealed class SshNetFileOperationTests : IClassFixture<SftpServerFixture>
{
    private const int LargeFileSize = 3 * 1024 * 1024 + 123; // not a multiple of the SFTP block size

    private readonly SftpServerFixture _server;

    public SshNetFileOperationTests(SftpServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public void CreateDirectory_creates_a_directory()
    {
        using var client = _server.Connect();
        var dir = $"/mkdir-{Guid.NewGuid():N}";

        client.CreateDirectory(dir);

        Assert.True(client.Exists(dir));
        Assert.True(Directory.Exists(_server.PhysicalPath(dir)));
    }

    [Fact]
    public void Upload_of_3MB_then_download_gives_the_same_bytes()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();
        var data = RandomNumberGenerator.GetBytes(LargeFileSize);

        Upload(client, dir + "/big.bin", data);
        var downloaded = Download(client, dir + "/big.bin");

        Assert.Equal(data.Length, downloaded.Length);
        Assert.True(data.AsSpan().SequenceEqual(downloaded), "The downloaded bytes differ from the uploaded bytes.");
        Assert.True(data.AsSpan().SequenceEqual(File.ReadAllBytes(_server.PhysicalPath(dir + "/big.bin"))),
            "The file on disk differs from the uploaded bytes.");
    }

    [Fact]
    public void ListDirectory_contains_the_uploaded_file()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();
        Upload(client, dir + "/listed.bin", RandomNumberGenerator.GetBytes(1000));

        var names = client.ListDirectory(dir).Select(f => f.Name).ToList();

        Assert.Contains("listed.bin", names);
    }

    [Fact]
    public void GetAttributes_of_a_file_gives_the_size_and_regular_file_type()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();
        Upload(client, dir + "/stat.bin", RandomNumberGenerator.GetBytes(LargeFileSize));

        var attributes = client.GetAttributes(dir + "/stat.bin");

        Assert.Equal(LargeFileSize, attributes.Size);
        Assert.True(attributes.IsRegularFile);
        Assert.False(attributes.IsDirectory);
    }

    [Fact]
    public void GetAttributes_of_a_directory_gives_directory_type()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();

        var attributes = client.GetAttributes(dir);

        Assert.True(attributes.IsDirectory);
        Assert.False(attributes.IsRegularFile);
    }

    [Fact]
    public void Exists_is_false_for_a_missing_path()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();

        Assert.False(client.Exists($"/missing-{Guid.NewGuid():N}"));
        Assert.False(client.Exists(dir + "/missing.bin"));
    }

    [Fact]
    public void GetAttributes_of_a_missing_path_throws_path_not_found()
    {
        using var client = _server.Connect();

        Assert.Throws<SftpPathNotFoundException>(() => client.GetAttributes($"/missing-{Guid.NewGuid():N}"));
    }

    [Fact]
    public void Overwrite_of_a_large_file_with_a_3_byte_file_gives_3_bytes()
    {
        using var client = _server.Connect();
        var path = _server.CreateUniqueDirectory() + "/overwrite.bin";
        Upload(client, path, RandomNumberGenerator.GetBytes(LargeFileSize));

        Upload(client, path, new byte[] { 1, 2, 3 });

        Assert.Equal(3, client.GetAttributes(path).Size);
        Assert.Equal(new byte[] { 1, 2, 3 }, Download(client, path));
    }

    [Fact]
    public void Upload_of_an_empty_stream_creates_an_empty_file()
    {
        using var client = _server.Connect();
        var path = _server.CreateUniqueDirectory() + "/empty.bin";

        Upload(client, path, Array.Empty<byte>());

        Assert.True(client.Exists(path));
        Assert.Equal(0, client.GetAttributes(path).Size);
        Assert.True(File.Exists(_server.PhysicalPath(path)));
    }

    [Fact]
    public void WriteAllText_then_AppendAllText_gives_the_concatenated_text()
    {
        using var client = _server.Connect();
        var path = _server.CreateUniqueDirectory() + "/text.txt";

        client.WriteAllText(path, "abc");
        client.AppendAllText(path, "def");

        Assert.Equal("abcdef", client.ReadAllText(path));
    }

    [Fact]
    public void RenameFile_moves_the_file()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();
        Upload(client, dir + "/old.bin", new byte[] { 42 });

        client.RenameFile(dir + "/old.bin", dir + "/new.bin");

        Assert.False(client.Exists(dir + "/old.bin"));
        Assert.True(client.Exists(dir + "/new.bin"));
        Assert.Equal(new byte[] { 42 }, Download(client, dir + "/new.bin"));
    }

    [Fact]
    public void DeleteFile_removes_the_file()
    {
        using var client = _server.Connect();
        var path = _server.CreateUniqueDirectory() + "/delete.bin";
        Upload(client, path, new byte[] { 1 });

        client.DeleteFile(path);

        Assert.False(client.Exists(path));
        Assert.False(File.Exists(_server.PhysicalPath(path)));
    }

    [Fact]
    public void DeleteDirectory_removes_an_empty_directory()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();

        client.DeleteDirectory(dir);

        Assert.False(client.Exists(dir));
        Assert.False(Directory.Exists(_server.PhysicalPath(dir)));
    }

    [Fact]
    public void Failed_open_of_a_missing_file_does_not_break_the_session()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();
        Upload(client, dir + "/present.txt", Encoding.UTF8.GetBytes("still works"));

        Assert.Throws<SftpPathNotFoundException>(() => client.OpenRead(dir + "/missing.txt").Dispose());

        Assert.Equal("still works", client.ReadAllText(dir + "/present.txt"));
        Assert.Contains("present.txt", client.ListDirectory(dir).Select(f => f.Name));
    }

    private static void Upload(SftpClient client, string path, byte[] data)
    {
        using var stream = new MemoryStream(data);
        client.UploadFile(stream, path);
    }

    private static byte[] Download(SftpClient client, string path)
    {
        using var stream = new MemoryStream();
        client.DownloadFile(path, stream);
        return stream.ToArray();
    }
}
