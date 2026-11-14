using SshServer.Interfaces.Users;
using System.Text;
using FreeSftpSharp.Tests.Storage;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.Permissions;
using SshServerModule.Events;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Events;

/// <summary>The events decorator over <see cref="InMemoryFileSystem"/>, with a recording bus and a fake clock.</summary>
public sealed class EventingFileSystemTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly Guid ConnectionId = Guid.Parse("6f1c2d3e-0000-4000-8000-000000000001");
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 11, 14, 10, 0, 0, TimeSpan.Zero));
    private readonly InMemoryFileSystem _storage;
    private readonly RecordingEventBus _bus = new();
    private readonly EventingFileSystem _fileSystem;

    public EventingFileSystemTests()
    {
        _storage = new InMemoryFileSystem(time: _time);
        _fileSystem = new EventingFileSystem(_storage, _bus, new User { Username = "alice" }, new ClientContext("SFTP", "192.0.2.7", ConnectionId), "memory", _time);
    }

    private static readonly FileOpenFlags CreateForWriting = FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate;

    private async Task UploadAsync(string path, string content, TimeSpan? duration = null)
    {
        await using var handle = await _fileSystem.OpenAsync(path, CreateForWriting, null, Ct);
        await handle.WriteAsync(0, Encoding.UTF8.GetBytes(content), Ct);
        if (duration is { } d)
            _time.Advance(d);
    }

    [Fact]
    public async Task An_upload_of_a_new_file_gives_PreUpload_Upload_and_FirstUpload()
    {
        await UploadAsync("/dir/../a.txt", "hello", TimeSpan.FromMilliseconds(1500));

        Assert.Equal([FileEventType.PreUpload, FileEventType.Upload, FileEventType.FirstUpload], _bus.FileEvents.Select(e => e.Type));
        var upload = _bus.FileEvents[1];
        Assert.Equal("alice", upload.Username);
        Assert.Equal("/a.txt", upload.VirtualPath);
        Assert.Equal(5, upload.FileSize);
        Assert.Equal(TimeSpan.FromMilliseconds(1500), upload.Elapsed);
        Assert.Equal(FileEventStatus.Ok, upload.Status);
        Assert.Equal(("SFTP", "192.0.2.7", ConnectionId.ToString(), "memory"), (upload.Protocol, upload.RemoteIp, upload.SessionId, upload.Provider));
        Assert.Equal(CreateForWriting, upload.OpenFlags);
        Assert.Equal(_time.GetUtcNow(), upload.Timestamp);
        Assert.Single(_bus.Asked);
    }

    [Fact]
    public async Task An_upload_over_an_existing_file_gives_no_FirstUpload()
    {
        await UploadAsync("/a.txt", "one");

        await UploadAsync("/a.txt", "second");

        Assert.Equal(2, _bus.FileEvents.Count(e => e.Type == FileEventType.Upload));
        Assert.Single(_bus.FileEvents, e => e.Type == FileEventType.FirstUpload);
        Assert.Equal(6, _bus.FileEvents.Last(e => e.Type == FileEventType.Upload).FileSize);
    }

    [Fact]
    public async Task A_denied_upload_throws_PermissionDenied_and_leaves_no_file()
    {
        _bus.Decide = e => e is FileEvent { Type: FileEventType.PreUpload } ? HookDecision.Deny("blocked by rule") : HookDecision.Allow;

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await _fileSystem.OpenAsync("/a.txt", CreateForWriting, null, Ct));

        Assert.Equal(FileSystemError.PermissionDenied, ex.Error);
        Assert.Null(await _storage.StatAsync("/a.txt", true, Ct));
        var pre = Assert.Single(_bus.FileEvents);
        Assert.Equal((FileEventType.PreUpload, FileEventStatus.Denied, "blocked by rule"), (pre.Type, pre.Status, pre.Message));
    }

    [Fact]
    public async Task A_download_gives_PreDownload_and_Download_with_the_bytes_read()
    {
        await UploadAsync("/a.txt", "0123456789");
        var before = _bus.FileEvents.Count;

        await using (var handle = await _fileSystem.OpenAsync("/a.txt", FileOpenFlags.Read, null, Ct))
        {
            var buffer = new byte[4];
            await handle.ReadAsync(0, buffer, Ct);
            await handle.ReadAsync(4, buffer, Ct);
        }

        var events = _bus.FileEvents.Skip(before).ToList();
        Assert.Equal([FileEventType.PreDownload, FileEventType.Download], events.Select(e => e.Type));
        Assert.Equal(8, events[1].FileSize);
    }

    [Fact]
    public async Task A_denied_download_does_not_open_the_file()
    {
        await UploadAsync("/a.txt", "x");
        _bus.Decide = e => e is FileEvent { Type: FileEventType.PreDownload } ? HookDecision.Deny("no") : HookDecision.Allow;

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await _fileSystem.OpenAsync("/a.txt", FileOpenFlags.Read, null, Ct));

        Assert.Equal(FileSystemError.PermissionDenied, ex.Error);
        Assert.DoesNotContain(_bus.FileEvents, e => e.Type == FileEventType.Download);
    }

    [Fact]
    public async Task A_delete_gives_PreDelete_and_Delete_with_the_size_and_a_deny_keeps_the_file()
    {
        await UploadAsync("/a.txt", "abc");
        await UploadAsync("/keep.txt", "abc");
        _bus.Decide = e => e is FileEvent { Type: FileEventType.PreDelete, VirtualPath: "/keep.txt" } ? HookDecision.Deny("keep it") : HookDecision.Allow;

        await _fileSystem.DeleteFileAsync("/a.txt", Ct);
        await Assert.ThrowsAsync<FileSystemException>(async () => await _fileSystem.DeleteFileAsync("/keep.txt", Ct));

        var delete = Assert.Single(_bus.FileEvents, e => e.Type == FileEventType.Delete);
        Assert.Equal(("/a.txt", 3L, FileEventStatus.Ok), (delete.VirtualPath, delete.FileSize, delete.Status));
        Assert.NotNull(await _storage.StatAsync("/keep.txt", true, Ct));
        Assert.Contains(_bus.FileEvents, e => e is { Type: FileEventType.PreDelete, VirtualPath: "/keep.txt", Status: FileEventStatus.Denied });
    }

    [Fact]
    public async Task Mkdir_rename_and_rmdir_give_one_event_each()
    {
        await _fileSystem.CreateDirectoryAsync("/d", Ct);
        await _fileSystem.RenameAsync("/d", "/e", RenameFlags.None, Ct);
        await _fileSystem.DeleteDirectoryAsync("/e", Ct);

        Assert.Equal([FileEventType.Mkdir, FileEventType.Rename, FileEventType.Rmdir], _bus.FileEvents.Select(e => e.Type));
        Assert.Equal(("/d", "/e"), (_bus.FileEvents[1].VirtualPath, _bus.FileEvents[1].VirtualTargetPath));
        Assert.Empty(_bus.Asked);
    }

    [Fact]
    public async Task A_failed_operation_gives_its_event_with_Error_and_throws_the_original_exception()
    {
        await _fileSystem.CreateDirectoryAsync("/d", Ct);

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await _fileSystem.CreateDirectoryAsync("/d", Ct));

        Assert.Equal(FileSystemError.AlreadyExists, ex.Error);
        var failed = _bus.FileEvents.Last();
        Assert.Equal((FileEventType.Mkdir, FileEventStatus.Error, ex.Message), (failed.Type, failed.Status, failed.Message));
    }

    [Fact]
    public async Task A_failed_open_for_writing_gives_an_Upload_with_Error()
    {
        await Assert.ThrowsAsync<FileSystemException>(async () => await _fileSystem.OpenAsync("/missing/a.txt", CreateForWriting, null, Ct));

        Assert.Equal([FileEventType.PreUpload, FileEventType.Upload], _bus.FileEvents.Select(e => e.Type));
        Assert.Equal(FileEventStatus.Error, _bus.FileEvents[1].Status);
    }

    [Fact]
    public async Task An_upload_that_the_permissions_refuse_gives_an_Upload_with_Error_and_no_file()
    {
        // The chain of the factory: events outside the permissions. Upload only, so the stat before the open is refused too.
        var user = new User { Username = "alice", Permissions = new() { ["/"] = FilePermissions.Download } };
        var permitted = PermissionFileSystem.Wrap(_storage, new EffectiveUserSettingsService().Resolve(user).Permissions);
        var fileSystem = new EventingFileSystem(permitted, _bus, user, new ClientContext("SFTP", "192.0.2.7"), "memory", _time);

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await fileSystem.OpenAsync("/a.txt", CreateForWriting, null, Ct));

        Assert.Equal(FileSystemError.PermissionDenied, ex.Error);
        Assert.Null(await _storage.StatAsync("/a.txt", true, Ct));
        Assert.Equal([FileEventType.PreUpload, FileEventType.Upload], _bus.FileEvents.Select(e => e.Type));
        Assert.Equal(FileEventStatus.Error, _bus.FileEvents[1].Status);
    }

    [Fact]
    public async Task Stat_list_and_attributes_give_no_events()
    {
        await _storage.CreateDirectoryAsync("/d", Ct);

        await _fileSystem.StatAsync("/d", true, Ct);
        await foreach (var _ in _fileSystem.ListAsync("/", Ct))
        {
        }
        await _fileSystem.SetAttributesAsync("/d", new FileAttributesUpdate { Permissions = 0x1C0 }, Ct);

        Assert.Empty(_bus.Published);
    }
}
