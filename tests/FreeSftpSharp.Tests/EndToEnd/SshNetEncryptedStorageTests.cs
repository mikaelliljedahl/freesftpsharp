using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using System.Security.Cryptography;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Storage.Encrypted;
using Microsoft.Extensions.Options;
using Renci.SshNet;
using Renci.SshNet.Common;
using SshServer.Filesystem.Encrypted;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>The server with the encrypted local disk ("local-encrypted") as the user root, as with <c>Storage:Encryption:Enabled</c>.</summary>
public sealed class EncryptedSftpServerFixture : SftpServerFixture
{
    protected override IFileSystemFactory CreateFileSystemFactory(IConnectionRegistry connections, IEventBus? events)
    {
        var keys = TestKeys.Provider("a", ("a", TestKeys.KeyA));
        return new StorageFileSystemFactory(
            new StorageProviderRegistry([new LocalDiskStorageProvider(), new EncryptedLocalStorageProvider(keys)]),
            new EncryptedUserRootStorageResolver(Options.Create(new EncryptedStorageOptions { Enabled = true })),
            new EffectivePermissionsService(), connections, events);
    }
}

/// <summary>SSH.NET against a server whose user root is encrypted: the disk has only ciphertext, SFTP gives the plaintext.</summary>
public sealed class SshNetEncryptedStorageTests : IClassFixture<EncryptedSftpServerFixture>
{
    private const int LargeFileSize = 3 * 1024 * 1024 + 123;

    private readonly EncryptedSftpServerFixture _server;

    public SshNetEncryptedStorageTests(EncryptedSftpServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public void An_uploaded_file_is_unreadable_on_disk_and_downloads_byte_for_byte()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();
        var data = RandomNumberGenerator.GetBytes(LargeFileSize);

        using (var upload = new MemoryStream(data))
            client.UploadFile(upload, dir + "/big.bin");

        var onDisk = File.ReadAllBytes(_server.PhysicalPath(dir + "/big.bin"));
        Assert.Equal("FSS1"u8.ToArray(), onDisk[..4]);
        Assert.Equal(EncryptedFileFormat.FileSize(LargeFileSize), onDisk.Length);
        Assert.Equal(-1, onDisk.AsSpan().IndexOf(data.AsSpan(1000, 32)));

        Assert.Equal(LargeFileSize, client.GetAttributes(dir + "/big.bin").Size);
        Assert.Equal(LargeFileSize, client.ListDirectory(dir).Single(f => f.Name == "big.bin").Length);
        Assert.True(data.AsSpan().SequenceEqual(Download(client, dir + "/big.bin")), "The downloaded bytes differ from the uploaded bytes.");
    }

    [Fact]
    public void A_read_at_an_offset_gives_the_same_bytes_as_the_plaintext()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();
        var data = RandomNumberGenerator.GetBytes(300_000);
        using (var upload = new MemoryStream(data))
            client.UploadFile(upload, dir + "/a.bin");

        using var stream = client.OpenRead(dir + "/a.bin");
        foreach (var offset in new[] { 65_530, 1, 200_000, 299_990 })
        {
            stream.Seek(offset, SeekOrigin.Begin);
            var buffer = new byte[100];
            var read = stream.ReadAtLeast(buffer, Math.Min(100, data.Length - offset), throwOnEndOfStream: false);
            Assert.True(data.AsSpan(offset, read).SequenceEqual(buffer.AsSpan(0, read)), $"offset {offset}");
        }
    }

    [Fact]
    public void A_changed_byte_on_disk_gives_an_error_not_wrong_data()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();
        using (var upload = new MemoryStream(RandomNumberGenerator.GetBytes(200_000)))
            client.UploadFile(upload, dir + "/a.bin");

        var path = _server.PhysicalPath(dir + "/a.bin");
        var bytes = File.ReadAllBytes(path);
        bytes[100_000] ^= 0x80;
        File.WriteAllBytes(path, bytes);

        var ex = Assert.ThrowsAny<SshException>(() => Download(client, dir + "/a.bin"));
        Assert.Contains("Failure", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.True(client.IsConnected);
    }

    [Fact]
    public void A_write_at_a_random_offset_is_refused_as_unsupported()
    {
        using var client = _server.Connect();
        var dir = _server.CreateUniqueDirectory();
        using (var upload = new MemoryStream(new byte[1000]))
            client.UploadFile(upload, dir + "/a.bin");

        var ex = Assert.ThrowsAny<SshException>(() =>
        {
            using var stream = client.Open(dir + "/a.bin", FileMode.Open, FileAccess.Write);
            stream.Seek(10, SeekOrigin.Begin);
            stream.Write([1, 2, 3]);
        });

        Assert.Contains("not supported", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1000, client.GetAttributes(dir + "/a.bin").Size);
    }

    private static byte[] Download(SftpClient client, string path)
    {
        using var stream = new MemoryStream();
        client.DownloadFile(path, stream);
        return stream.ToArray();
    }
}
