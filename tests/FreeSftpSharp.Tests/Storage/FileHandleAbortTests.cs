using System.Text;
using FreeSftpSharp.Tests.Sftp;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using SshServerModule.Connections;
using SshServerModule.Events;
using SshServerModule.Storage;
using FreeSftpSharp.Tests.Events;
using FxSsh.Services.Sftp;
using static FreeSftpSharp.Tests.Sftp.SftpEngineClient;

namespace FreeSftpSharp.Tests.Storage;

/// <summary>
/// An abort (a session that ended without a CLOSE) travels from the SFTP engine through the adapter and each storage
/// decorator to the backend as <see cref="IFileHandle.AbortAsync"/>; SSH_FXP_CLOSE stays a normal close.
/// </summary>
public sealed class FileHandleAbortTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private const FileOpenFlags CreateForWriting = FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate;

    private static async Task AbortAfterWriteAsync(IFileSystem fileSystem)
    {
        var handle = await fileSystem.OpenAsync("/a.txt", CreateForWriting, null, Ct);
        await handle.WriteAsync(0, "data"u8.ToArray(), Ct);
        await handle.AbortAsync();
    }

    [Fact]
    public async Task The_permission_decorator_forwards_an_abort()
    {
        var spy = new AbortSpyFileSystem(new InMemoryFileSystem());
        var rules = new EffectivePermissions(
            new Dictionary<string, FilePermissions> { ["/"] = FilePermissions.All, ["/zz-unused"] = FilePermissions.All },
            new Dictionary<string, PathFilter> { ["/"] = new PathFilter { DeniedPatterns = ["never-used-name"] } });

        await AbortAfterWriteAsync(new PermissionFileSystem(spy, rules));

        Assert.Equal(["Abort"], spy.Closes);
    }

    [Fact]
    public async Task The_virtual_folder_router_gives_the_handle_of_the_storage_so_an_abort_reaches_it()
    {
        var root = new AbortSpyFileSystem(new InMemoryFileSystem());
        var mounted = new AbortSpyFileSystem(new InMemoryFileSystem());
        var router = new MountedFileSystem(root, [new MountedFileSystem.Mount("/shared", mounted)]);

        await AbortAfterWriteAsync(router);
        var inFolder = await router.OpenAsync("/shared/b.txt", CreateForWriting, null, Ct);
        await inFolder.WriteAsync(0, "data"u8.ToArray(), Ct);
        await inFolder.AbortAsync();
        await using (await router.OpenAsync("/shared/c.txt", CreateForWriting, null, Ct))
        {
        }

        Assert.Equal(["Abort"], root.Closes);
        Assert.Equal(["Abort", "Dispose"], mounted.Closes);
    }

    [Fact]
    public async Task The_connection_tracking_decorator_forwards_an_abort_and_ends_the_transfer()
    {
        var registry = new ConnectionRegistry(new FakeTimeProvider());
        var id = registry.Register(new ConnectionRegistration(ConnectionProtocols.Sftp, "127.0.0.1:1", _ => Task.CompletedTask)).Id;
        var spy = new AbortSpyFileSystem(new InMemoryFileSystem());

        await AbortAfterWriteAsync(new ConnectionTrackingFileSystem(spy, registry, id));

        Assert.Equal(["Abort"], spy.Closes);
        Assert.Empty(registry.Get(id)!.Transfers);
    }

    [Fact]
    public async Task The_events_decorator_forwards_an_abort_and_publishes_a_failed_upload()
    {
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 11, 14, 10, 0, 0, TimeSpan.Zero));
        var bus = new RecordingEventBus();
        var spy = new AbortSpyFileSystem(new InMemoryFileSystem(time: time));
        var fileSystem = new EventingFileSystem(spy, bus, new User { Username = "alice" }, new ClientContext("SFTP", "192.0.2.7", Guid.NewGuid()), "memory", time);

        await AbortAfterWriteAsync(fileSystem);

        Assert.Equal(["Abort"], spy.Closes);
        var upload = Assert.Single(bus.FileEvents, e => e.Type == FileEventType.Upload);
        Assert.Equal(FileEventStatus.Error, upload.Status);
        Assert.DoesNotContain(bus.FileEvents, e => e.Type == FileEventType.FirstUpload);
    }

    [Fact]
    public void A_lost_session_aborts_the_open_files_and_a_CLOSE_request_closes_a_file_normally()
    {
        var spy = new AbortSpyFileSystem(new InMemoryFileSystem());
        using var client = new SftpEngineClient(spy);
        client.Service.OnData(Init());
        client.Responses.Clear();
        const SftpOpenFlags flags = SftpOpenFlags.Write | SftpOpenFlags.Create | SftpOpenFlags.Truncate;

        var closed = client.OpenHandle("/closed.txt", flags);
        Assert.Equal(SSH_FX_OK, client.Write(closed, 0, Encoding.ASCII.GetBytes("complete")));
        Assert.Equal(SSH_FX_OK, client.Close(closed));
        var open = client.OpenHandle("/open.txt", flags);
        Assert.Equal(SSH_FX_OK, client.Write(open, 0, Encoding.ASCII.GetBytes("partial")));
        Assert.Equal(["Dispose"], spy.Closes);

        client.Service.OnClose();

        Assert.Equal(["Dispose", "Abort"], spy.Closes);
        Assert.Equal(SSH_FX_FAILURE, client.Write(open, 0, [1]));
    }
}
