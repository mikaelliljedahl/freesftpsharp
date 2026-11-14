using System.Text;
using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Shares;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Shares;

/// <summary>
/// The storage factory with <see cref="ClientContext.PermissionMask"/> and <see cref="ClientContext.Metadata"/> (#70): the
/// owner's permissions intersected with the scope of a share, and the share id in the file events.
/// </summary>
public sealed class ShareStorageTests : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly TempDirectory _root = new();
    private readonly InMemorySettingsRepository _repository = new(new ServerSettings());
    private readonly RecordingEventBus _bus = new();
    private readonly StorageFileSystemFactory _factory;
    private readonly User _owner;

    public ShareStorageTests()
    {
        _factory = TestStorage.Factory([new LocalDiskStorageProvider()], _ => new UserStorageResolver(new UserRootDefaultStorage(), _repository),
            events: _bus, repository: _repository);
        _owner = new User
        {
            Username = "owner",
            UserRootDirectory = _root.Path,
            Permissions = new Dictionary<string, FilePermissions> { ["/"] = FilePermissions.All, ["/private"] = FilePermissions.List },
        };
        Assert.True(_repository.AddUser(_owner));
        Directory.CreateDirectory(Path.Combine(_root.Path, "private"));
        File.WriteAllText(Path.Combine(_root.Path, "a.txt"), "hello");
        File.WriteAllText(Path.Combine(_root.Path, "private", "p.txt"), "secret");
    }

    private ValueTask<IFileSystem> CreateAsync(ShareScope scope) => _factory.CreateAsync(_owner, new ClientContext("HTTPShare", "192.0.2.9")
    {
        PermissionMask = ShareRules.PermissionMask(scope, allowOverwrite: false),
        Metadata = new Dictionary<string, string> { ["shareId"] = "the-id" },
    }, Ct);

    [Fact]
    public async Task A_read_share_downloads_but_never_writes_and_the_events_carry_the_metadata()
    {
        var fileSystem = await CreateAsync(ShareScope.Read);

        await using (var handle = await fileSystem.OpenAsync("/a.txt", FileOpenFlags.Read, null, Ct))
            Assert.Equal(5, (await handle.StatAsync(Ct)).Size);
        var write = await Assert.ThrowsAsync<FileSystemException>(async () =>
            await fileSystem.OpenAsync("/new.txt", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct));
        Assert.Equal(FileSystemError.PermissionDenied, write.Error);
        await Assert.ThrowsAsync<FileSystemException>(async () => await fileSystem.DeleteFileAsync("/a.txt", Ct));
        Assert.True(File.Exists(Path.Combine(_root.Path, "a.txt")));

        var download = Assert.Single(_bus.FileEvents, e => e.Type == FileEventType.Download);
        Assert.Equal("HTTPShare", download.Protocol);
        Assert.Equal("the-id", download.Metadata!["shareId"]);
    }

    [Fact]
    public async Task The_share_never_has_more_than_the_owner()
    {
        var fileSystem = await CreateAsync(ShareScope.ReadWrite);

        // The owner may only list /private: the share may not download from there either.
        var denied = await Assert.ThrowsAsync<FileSystemException>(async () => await fileSystem.OpenAsync("/private/p.txt", FileOpenFlags.Read, null, Ct));
        Assert.Equal(FileSystemError.PermissionDenied, denied.Error);
        var upload = await Assert.ThrowsAsync<FileSystemException>(async () =>
            await fileSystem.OpenAsync("/private/new.txt", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct));
        Assert.Equal(FileSystemError.PermissionDenied, upload.Error);
    }

    [Fact]
    public async Task A_write_share_uploads_new_files_but_does_not_overwrite_or_download()
    {
        var fileSystem = await CreateAsync(ShareScope.Write);

        await using (var handle = await fileSystem.OpenAsync("/in.txt", FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Exclusive, null, Ct))
            await handle.WriteAsync(0, Encoding.UTF8.GetBytes("x"), Ct);
        Assert.True(File.Exists(Path.Combine(_root.Path, "in.txt")));
        var overwrite = await Assert.ThrowsAsync<FileSystemException>(async () =>
            await fileSystem.OpenAsync("/a.txt", FileOpenFlags.Write | FileOpenFlags.Truncate, null, Ct));
        Assert.Equal(FileSystemError.PermissionDenied, overwrite.Error);
        await Assert.ThrowsAsync<FileSystemException>(async () => await fileSystem.OpenAsync("/a.txt", FileOpenFlags.Read, null, Ct));
    }

    public void Dispose() => _root.Dispose();
}
