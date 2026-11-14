using System.Diagnostics;
using System.Security.Cryptography;
using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Renci.SshNet.Common;
using SshServer.Interfaces.Events;
using SshServerModule.Events;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// The server with the real event bus, a recording sink, a sink that blocks for the whole run and a hook that refuses
/// uploads whose name starts with "denied".
/// </summary>
public sealed class EventServerFixture : SftpServerFixture
{
    public RecordingEventSink Sink { get; } = new();
    public BlockingEventSink BlockedSink { get; } = new();
    public ChannelEventBus? Bus { get; private set; }

    protected override IEventBus CreateEventBus()
    {
        var hook = new DelegateEventHook(e => e is FileEvent { Type: FileEventType.PreUpload } file
            && file.VirtualPath.Contains("/denied", StringComparison.Ordinal) ? HookDecision.Deny("uploads named denied* are refused") : HookDecision.Allow);
        Bus = new ChannelEventBus([BlockedSink, Sink], [hook], NullLogger<ChannelEventBus>.Instance);
        return Bus;
    }
}

/// <summary>Events of real SFTP sessions (#65): file events with size, user, address and status, auth events, deny of a hook.</summary>
public sealed class EventEndToEndTests : IClassFixture<EventServerFixture>
{
    private readonly EventServerFixture _server;

    public EventEndToEndTests(EventServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task An_upload_gives_one_PreUpload_and_one_Upload_with_size_user_ip_and_status()
    {
        var directory = _server.CreateUniqueDirectory("ev");
        var path = directory + "/upload.bin";
        var data = RandomNumberGenerator.GetBytes(100_000);

        using (var client = _server.Connect())
        {
            using var stream = new MemoryStream(data);
            client.UploadFile(stream, path);
        }

        var uploads = await _server.Sink.WaitForAsync<FileEvent>(e => e.Type == FileEventType.Upload && e.VirtualPath == path);
        var upload = Assert.Single(uploads);
        Assert.Single(_server.Sink.Of<FileEvent>(e => e.Type == FileEventType.PreUpload && e.VirtualPath == path));
        Assert.Equal(data.Length, upload.FileSize);
        Assert.Equal(_server.Username, upload.Username);
        Assert.Equal("127.0.0.1", upload.RemoteIp);
        Assert.Equal("SFTP", upload.Protocol);
        Assert.Equal("local", upload.Provider);
        Assert.Equal(FileEventStatus.Ok, upload.Status);
        Assert.NotNull(upload.Elapsed);
        // The session id is the connection id of the registry (#57), the same as in the login event of the connection.
        Assert.True(Guid.TryParse(upload.SessionId, out _), $"Not a connection id: {upload.SessionId}");
        Assert.Contains(_server.Sink.Of<AuthEvent>(), e => e is { Type: AuthEventType.LoginOk, Method: "password", RemoteIp: "127.0.0.1" }
            && e.Username == _server.Username && e.SessionId == upload.SessionId);
    }

    [Fact]
    public async Task A_denied_upload_gives_permission_denied_and_leaves_no_file()
    {
        var directory = _server.CreateUniqueDirectory("ev");
        var path = directory + "/denied.txt";

        using (var client = _server.Connect())
        {
            using var stream = new MemoryStream([1, 2, 3]);
            Assert.Throws<SftpPermissionDeniedException>(() => client.UploadFile(stream, path));
        }

        Assert.False(File.Exists(_server.PhysicalPath(path)));
        var pre = await _server.Sink.WaitForAsync<FileEvent>(e => e.Type == FileEventType.PreUpload && e.VirtualPath == path);
        Assert.Equal(FileEventStatus.Denied, Assert.Single(pre).Status);
        Assert.Empty(_server.Sink.Of<FileEvent>(e => e.Type == FileEventType.Upload && e.VirtualPath == path));
    }

    [Fact]
    public async Task A_wrong_password_gives_LoginFailed()
    {
        using (var client = _server.CreateClient(password: "wrong-password", username: "nobody-" + Guid.NewGuid().ToString("N")[..8]))
            Assert.Throws<SshAuthenticationException>(() => client.Connect());

        var failed = await _server.Sink.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.LoginFailed && e.Username!.StartsWith("nobody-", StringComparison.Ordinal));
        Assert.Equal(("password", "unknown user", "127.0.0.1"), (failed[0].Method, failed[0].Reason, failed[0].RemoteIp));
    }

    [Fact]
    public async Task A_sink_that_blocks_does_not_slow_a_transfer()
    {
        // BlockedSink has not finished a single event since the server started; every transfer of this class runs beside it.
        var directory = _server.CreateUniqueDirectory("ev");
        var data = RandomNumberGenerator.GetBytes(1024 * 1024);
        var watch = Stopwatch.StartNew();

        using (var client = _server.Connect())
        {
            for (var i = 0; i < 5; i++)
            {
                using var stream = new MemoryStream(data);
                client.UploadFile(stream, $"{directory}/file{i}.bin");
            }
        }
        watch.Stop();

        await _server.Sink.WaitForAsync<FileEvent>(e => e.Type == FileEventType.Upload && e.VirtualPath.StartsWith(directory + "/", StringComparison.Ordinal), 5);
        Assert.Equal(0, _server.BlockedSink.Handled);
        Assert.Equal(0, _server.Bus!.PublisherWaits);
        // Five 1 MiB uploads over loopback take well under a second; a transfer that waited for the sink would never end.
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(30), $"The uploads took {watch.Elapsed}.");
    }

    [Fact]
    public async Task An_upload_with_OpenSSH_sftp_gives_PreUpload_and_Upload()
    {
        OpenSshSftp.SkipIfUnavailable();
        var local = Path.Combine(_server.TempDirectory, "local-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(local);
        var data = RandomNumberGenerator.GetBytes(50_000);
        File.WriteAllBytes(Path.Combine(local, "put.bin"), data);
        var directory = _server.CreateUniqueDirectory("ossh-ev");

        var result = await OpenSshSftp.RunAsync(_server, local, "cd " + directory, $"put {OpenSshSftp.Quote(Path.Combine(local, "put.bin"))} put.bin", "pwd");

        Assert.True(File.Exists(_server.PhysicalPath(directory + "/put.bin")), result.ToString());
        var path = directory + "/put.bin";
        var upload = Assert.Single(await _server.Sink.WaitForAsync<FileEvent>(e => e.Type == FileEventType.Upload && e.VirtualPath == path));
        Assert.Single(_server.Sink.Of<FileEvent>(e => e.Type == FileEventType.PreUpload && e.VirtualPath == path));
        Assert.Equal((data.Length, FileEventStatus.Ok, "127.0.0.1"), (upload.FileSize, upload.Status, upload.RemoteIp));
    }
}
