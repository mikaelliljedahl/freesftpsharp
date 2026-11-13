using System.Text;
using FreeSftpSharp.Tests.Storage;
using FxSsh.Services.Sftp;
using SshServer.Interfaces.Storage;
using static FreeSftpSharp.Tests.Sftp.SftpEngineClient;

namespace FreeSftpSharp.Tests.Sftp;

/// <summary>
/// <c>SftpFileSystemAdapter</c> on an <see cref="InMemoryFileSystem"/>: the SFTP engine works on any backend of the
/// storage abstraction, each <see cref="FileSystemError"/> gives its SSH_FX status code, and a backend without a
/// capability answers SSH_FX_OP_UNSUPPORTED.
/// </summary>
public sealed class SftpInMemoryStorageTests
{
    private const SftpOpenFlags WriteCreateTruncate = SftpOpenFlags.Write | SftpOpenFlags.Create | SftpOpenFlags.Truncate;

    private static SftpEngineClient Connect(IFileSystem fileSystem)
    {
        var client = new SftpEngineClient(fileSystem);
        client.Service.OnData(Init());
        client.Responses.Clear();
        return client;
    }

    [Fact]
    public void Upload_list_download_rename_and_remove_work_in_memory()
    {
        using var client = Connect(new InMemoryFileSystem());

        Assert.Equal(SSH_FX_OK, client.MakeDirectory("/dir"));
        var handle = client.OpenHandle("/dir/a.txt", WriteCreateTruncate);
        Assert.Equal(SSH_FX_OK, client.Write(handle, 0, Encoding.ASCII.GetBytes("hello")));
        Assert.Equal(SSH_FX_OK, client.Close(handle));

        Assert.Equal([".", "..", "a.txt"], client.ReadDirectory("/dir").Select(e => e.Name).Order(StringComparer.Ordinal));
        Assert.Equal(5ul, client.Stat("/dir/a.txt").Size);
        Assert.Equal(SSH_FX_OK, client.Rename("/dir/a.txt", "/dir/b.txt"));

        var read = client.OpenHandle("/dir/b.txt", SftpOpenFlags.Read);
        Assert.Equal("hello", Encoding.ASCII.GetString(client.Read(read, 0, 100).Payload.ReadBinary()));
        Assert.Equal(SSH_FX_EOF, client.Read(read, 5, 100).StatusCode);
        Assert.Equal(SSH_FX_OK, client.Close(read));

        Assert.Equal(SSH_FX_OK, client.Status(SSH_FXP_REMOVE, "/dir/b.txt"));
        Assert.Equal(SSH_FX_OK, client.Status(SSH_FXP_RMDIR, "/dir"));
        Assert.Equal([".", ".."], client.ReadDirectory("/").Select(e => e.Name).Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData(FileSystemError.NoSuchFile, SSH_FX_NO_SUCH_FILE)]
    [InlineData(FileSystemError.PermissionDenied, SSH_FX_PERMISSION_DENIED)]
    [InlineData(FileSystemError.OpNotSupported, SSH_FX_OP_UNSUPPORTED)]
    [InlineData(FileSystemError.InvalidPath, SSH_FX_BAD_MESSAGE)]
    [InlineData(FileSystemError.Failure, SSH_FX_FAILURE)]
    [InlineData(FileSystemError.NotADirectory, SSH_FX_FAILURE)]
    [InlineData(FileSystemError.IsADirectory, SSH_FX_FAILURE)]
    [InlineData(FileSystemError.DirectoryNotEmpty, SSH_FX_FAILURE)]
    [InlineData(FileSystemError.AlreadyExists, SSH_FX_FAILURE)]
    [InlineData(FileSystemError.QuotaExceeded, SSH_FX_FAILURE)]
    public void Each_file_system_error_gives_its_status_code_without_the_backend_message(FileSystemError error, uint expected)
    {
        using var client = Connect(new ThrowingFileSystem(() => new FileSystemException(error, "backend detail /srv/physical/path")));

        foreach (var response in new[] { client.SendPath(SSH_FXP_STAT, "/a"), client.SendPath(SSH_FXP_RMDIR, "/a"), client.SendPath(SSH_FXP_OPENDIR, "/a") })
        {
            Assert.Equal(expected, response.StatusCode);
            Assert.DoesNotContain("/srv/physical/path", response.StatusMessage);
        }
    }

    [Theory]
    [InlineData(SSH_FXP_OPEN)]
    [InlineData(SSH_FXP_REMOVE)]
    public void Is_a_directory_of_open_and_remove_gives_permission_denied(byte type)
    {
        using var client = Connect(new ThrowingFileSystem(() => new FileSystemException(FileSystemError.IsADirectory, "is a directory")));

        var status = type == SSH_FXP_OPEN ? client.Open("/dir", SftpOpenFlags.Read).StatusCode : client.Status(SSH_FXP_REMOVE, "/dir");

        Assert.Equal(SSH_FX_PERMISSION_DENIED, status);
    }

    [Fact]
    public void Object_store_accepts_a_sequential_upload_and_answers_op_unsupported_for_the_rest()
    {
        using var client = Connect(new InMemoryFileSystem(StorageCapabilities.None));

        var handle = client.OpenHandle("/a.bin", WriteCreateTruncate);
        Assert.Equal(SSH_FX_OK, client.Write(handle, 0, new byte[100]));
        Assert.Equal(SSH_FX_OK, client.Write(handle, 100, new byte[100]));
        Assert.Equal(SSH_FX_OP_UNSUPPORTED, client.Write(handle, 50, new byte[10]));   // random access
        Assert.Equal(SSH_FX_OP_UNSUPPORTED, client.Write(handle, 300, new byte[10]));  // past the end
        Assert.Equal(SSH_FX_OK, client.Close(handle));

        Assert.Equal(200ul, client.Stat("/a.bin").Size);
        Assert.Equal(SSH_FX_OP_UNSUPPORTED, client.Rename("/a.bin", "/b.bin"));
        Assert.Equal(SSH_FX_OP_UNSUPPORTED, client.SetStat("/a.bin", new SftpFileAttributes { ModificationTime = 1_700_000_000 }));
        Assert.Equal(SSH_FX_OP_UNSUPPORTED, client.SetStat("/a.bin", new SftpFileAttributes { Size = 0 }));
        Assert.Equal(SSH_FX_OP_UNSUPPORTED, client.Open("/a.bin", SftpOpenFlags.Write | SftpOpenFlags.Append).StatusCode);
    }

    [Fact]
    public void Statvfs_of_a_storage_without_a_size_fails()
    {
        using var client = Connect(new InMemoryFileSystem());

        var status = client.Extended("statvfs@openssh.com", w => w.Write("/", Encoding.UTF8)).StatusCode;

        Assert.Equal(SSH_FX_FAILURE, status);
    }
}
