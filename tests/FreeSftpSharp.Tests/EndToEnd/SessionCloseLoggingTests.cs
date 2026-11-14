using System.Net;
using System.Net.Sockets;
using System.Reflection;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Sftp;
using FreeSftpSharp.Tests.Storage;
using FxSsh;
using FxSsh.Logging;
using FxSsh.Messages.Connection;
using FxSsh.Services;
using FxSsh.Services.Sftp;
using FxSsh.SshServerModule;
using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Interfaces;
using SshServerModule.Sftp;
using static FreeSftpSharp.Tests.Infrastructure.OpenSshSftp;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// A client that ends its session normally must not give an Error line in the server log (#100).
/// <para>
/// FxSsh handles the channel messages of a session in a queue on another task. OpenSSH sends CHANNEL_CLOSE and
/// SSH_MSG_DISCONNECT right after each other; when the queue is late (a busy thread pool), the session closes its
/// channels while the CHANNEL_CLOSE is still queued, and the queue then handled a message for a channel that no
/// longer exists. The tests on <see cref="ClosingRaceServer"/> make the queue late on purpose: a handler of the
/// client's CHANNEL_EOF waits until the session has closed its channels. A real protocol error in an open session
/// must still be logged at Error.
/// </para>
/// <para>
/// The FxSsh log is static, so this class captures it in the collection that runs alone.
/// </para>
/// </summary>
[Collection(SftpFailureLoggingTests.Name)]
public sealed class SessionCloseLoggingTests : IClassFixture<SftpServerFixture>, IDisposable
{
    private readonly SftpServerFixture _server;
    private readonly CapturingSink _sink = new();

    public SessionCloseLoggingTests(SftpServerFixture server)
    {
        _server = server;
        Log.Configure(new LogOptions { MinLevel = LogLevel.Trace, Sink = _sink });
    }

    [Fact]
    public async Task OpenSsh_sftp_sessions_with_put_and_rm_log_no_error()
    {
        SkipIfUnavailable();
        var local = CreateLocalDirectory();
        var remote = _server.CreateUniqueDirectory("close");

        for (var i = 0; i < 20; i++)
        {
            var result = await RunAsync(_server, local, "cd " + remote, "put file.bin", "rm file.bin", "pwd");
            Assert.True(result.ExitedByItself && result.ExitCode == 0, $"sftp session {i} did not end normally.{Environment.NewLine}{result}");
        }

        await AssertNoErrorLoggedAsync(() => _server.Connections.GetAll().Count == 0);
    }

    [Fact]
    public async Task SshNet_sessions_with_upload_and_delete_log_no_error()
    {
        var remote = _server.CreateUniqueDirectory("close");

        for (var i = 0; i < 50; i++)
        {
            using var client = _server.Connect();
            client.UploadFile(new MemoryStream(new byte[16 * 1024]), remote + "/file.bin");
            client.DeleteFile(remote + "/file.bin");
            client.Disconnect();
        }

        await AssertNoErrorLoggedAsync(() => _server.Connections.GetAll().Count == 0);
    }

    [Fact]
    public async Task OpenSsh_close_while_the_channel_messages_are_still_queued_logs_no_error()
    {
        SkipIfUnavailable();
        await using var server = await ClosingRaceServer.StartAsync(delayAfterEof: true);
        var local = CreateLocalDirectory();

        var result = await RunWithArgumentsAsync(_server, local, server.Port, [], "put file.bin", "rm file.bin", "pwd");

        Assert.True(result.ExitedByItself && result.ExitCode == 0, $"The sftp session did not end normally.{Environment.NewLine}{result}");
        Assert.True(await server.WaitForTeardownAsync(), "The session did not close its channels.");
        await AssertNoErrorLoggedAsync(() => server.QueueDrained);
    }

    [Fact]
    public async Task SshNet_close_while_the_channel_messages_are_still_queued_logs_no_error()
    {
        await using var server = await ClosingRaceServer.StartAsync(delayAfterEof: true);

        using (var client = new Renci.SshNet.SftpClient(SftpServerFixture.Host, server.Port, "anyone", "anything"))
        {
            client.Connect();
            client.UploadFile(new MemoryStream(new byte[16 * 1024]), "/file.bin");
            client.DeleteFile("/file.bin");
            client.Disconnect();
        }

        Assert.True(await server.WaitForTeardownAsync(), "The session did not close its channels.");
        await AssertNoErrorLoggedAsync(() => server.QueueDrained);
    }

    [Fact]
    public async Task Message_for_an_unknown_channel_in_an_open_session_is_logged_as_an_error()
    {
        await using var server = await ClosingRaceServer.StartAsync(delayAfterEof: false);
        using var client = new Renci.SshNet.SshClient(SftpServerFixture.Host, server.Port, "anyone", "anything");
        client.Connect();
        var connectionService = await server.ConnectionService;

        // A CHANNEL_EOF for a channel that the client never opened, given to the service as the session gives it
        // a message from the wire.
        typeof(ConnectionService).GetMethod("HandleMessageCore", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(connectionService, [new ChannelEofMessage { RecipientChannel = 4242 }]);

        Assert.True(await WaitUntilAsync(() => _sink.Entries().Any(e => e.Level >= LogLevel.Fail)),
            "The message for an unknown channel was not logged as an error." + Environment.NewLine + _sink);
        var entry = Assert.Single(_sink.Entries(), e => e.Level >= LogLevel.Fail);
        Assert.Equal(LogLevel.Fail, entry.Level);
        Assert.Contains("Connection service message handling failed", entry.Message);
        Assert.True(client.IsConnected);
    }

    public void Dispose()
    {
        Log.Configure(new LogOptions());
    }

    private string CreateLocalDirectory()
    {
        var local = Path.Combine(_server.TempDirectory, "local-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(local);
        File.WriteAllBytes(Path.Combine(local, "file.bin"), new byte[64 * 1024]);
        return local;
    }

    /// <summary>The server finishes a session after the client has gone, so wait until it is done.</summary>
    private async Task AssertNoErrorLoggedAsync(Func<bool> sessionsDone)
    {
        Assert.True(await WaitUntilAsync(sessionsDone), "The server did not finish the sessions.");
        await Task.Delay(100, TestContext.Current.CancellationToken);
        var errors = _sink.Entries().Where(e => e.Level >= LogLevel.Fail).ToList();
        Assert.True(errors.Count == 0, $"{errors.Count} error entries:{Environment.NewLine}" +
            string.Join(Environment.NewLine, errors.Select(e => $"{e.Level} {e.Message} {e.Exception}")));
    }

    private static async Task<bool> WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 100; i++)
        {
            if (condition())
                return true;
            await Task.Delay(50, TestContext.Current.CancellationToken);
        }
        return condition();
    }

    /// <summary>
    /// An FxSsh server with the SFTP engine on an <see cref="InMemoryFileSystem"/> that accepts every login. With
    /// <c>delayAfterEof</c>, a handler of the client's CHANNEL_EOF blocks the channel message queue until the session
    /// has closed its channels, so the messages after the EOF (the client's CHANNEL_CLOSE) are still queued then.
    /// </summary>
    private sealed class ClosingRaceServer : IAsyncDisposable
    {
        private readonly FxSsh.SshServer _server;
        private readonly TaskCompletionSource<ConnectionService> _connectionService = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _teardown = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly bool _delayAfterEof;
        private volatile bool _eofHandled;

        private ClosingRaceServer(int port, bool delayAfterEof)
        {
            Port = port;
            _delayAfterEof = delayAfterEof;
            _server = new FxSsh.SshServer(new StartingInfo(IPAddress.Loopback, port, "SSH-2.0-ClosingRaceServer"));
            foreach (var key in HostKeys.Load(new InMemorySettingsRepository(new ServerSettings { ServerRsaKey = TestCredentials.HostKey })))
                _server.AddHostKey(key.Algorithm, key.Pem);
            _server.ConnectionAccepted += (_, session) => session.ServiceRegistered += (_, service) =>
            {
                if (service is UserAuthService auth)
                    auth.UserAuth += (_, args) => args.Result = true;
                else if (service is ConnectionService connection)
                {
                    connection.SubsystemRequested += (_, args) => AttachSftp(args);
                    _connectionService.TrySetResult(connection);
                }
            };
        }

        public int Port { get; }

        public Task<ConnectionService> ConnectionService => _connectionService.Task.WaitAsync(TimeSpan.FromSeconds(10));

        /// <summary>True when the queue has handled the client's CHANNEL_EOF (and the delay after it).</summary>
        public bool QueueDrained => _eofHandled;

        public static async Task<ClosingRaceServer> StartAsync(bool delayAfterEof)
        {
            var server = new ClosingRaceServer(FreeTcpPort(), delayAfterEof);
            await server._server.StartAsync(TestContext.Current.CancellationToken);
            return server;
        }

        /// <summary>Waits until the delayed EOF handler has seen the session close the SFTP channel because the connection ended.</summary>
        public async Task<bool> WaitForTeardownAsync()
            => await Task.WhenAny(_teardown.Task, Task.Delay(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken)) == _teardown.Task;

        private void AttachSftp(SubsystemRequestedArgs args)
        {
            if (args.Name != "sftp")
                return;
            var channel = args.Channel;
            new SftpService(new SftpFileSystemAdapter(new InMemoryFileSystem(), NullLogger.Instance, "anyone")).Attach(channel);
            // Subscribed after Attach, so the SFTP engine has already started to send its EOF and CLOSE.
            channel.EofReceived += (_, _) =>
            {
                if (_delayAfterEof)
                {
                    // The session marks the channel force-closed when the connection ends, just before it removes it.
                    if (SpinWait.SpinUntil(() => channel.IsForceClosed, TimeSpan.FromSeconds(10)))
                        _teardown.TrySetResult();
                    Thread.Sleep(100);
                }
                _eofHandled = true;
            };
            args.Agreed = true;
        }

        public async ValueTask DisposeAsync()
        {
            await _server.StopAsync();
            _server.Dispose();
        }

        private static int FreeTcpPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                return ((IPEndPoint)listener.LocalEndpoint).Port;
            }
            finally
            {
                listener.Stop();
            }
        }
    }

    private sealed class CapturingSink : ILogSink
    {
        private readonly List<(LogLevel Level, string Message, Exception? Exception)> _entries = [];

        public void Write(LogLevel level, string message, Exception? exception = null)
        {
            lock (_entries)
                _entries.Add((level, message, exception));
        }

        public List<(LogLevel Level, string Message, Exception? Exception)> Entries()
        {
            lock (_entries)
                return _entries.ToList();
        }

        public override string ToString() =>
            string.Join(Environment.NewLine, Entries().Select(e => $"{e.Level} {e.Message}"));
    }
}
