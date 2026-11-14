using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Interfaces.Events;
using SshServerModule.Events;
using SshServerModule.Observability;

namespace FreeSftpSharp.Tests.Observability;

/// <summary>The server with the real event bus and the metrics sink of the core.</summary>
public sealed class MetricsServerFixture : SftpServerFixture
{
    public FreeSftpSharpMetrics? Metrics { get; private set; }
    public RecordingEventSink Sink { get; } = new();

    protected override IEventBus CreateEventBus()
    {
        Metrics = new FreeSftpSharpMetrics(Connections);
        return new ChannelEventBus([Metrics, Sink], [], NullLogger<ChannelEventBus>.Instance);
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        Metrics?.Dispose();
    }
}

public sealed class MetricsEndToEndTests : IClassFixture<MetricsServerFixture>
{
    private readonly MetricsServerFixture _server;

    public MetricsEndToEndTests(MetricsServerFixture server) => _server = server;

    [Fact]
    public async Task An_sftp_upload_and_download_move_the_transfer_counters_and_the_connection_gauge()
    {
        using var collector = new MeasurementCollector(_server.Metrics!.Meter);
        var path = _server.CreateUniqueDirectory("metrics") + "/m.bin";
        var data = new byte[70_000];
        new Random(1).NextBytes(data);

        using (var client = _server.Connect())
        {
            using (var stream = new MemoryStream(data))
                client.UploadFile(stream, path);
            using (var sink = new MemoryStream())
                client.DownloadFile(path, sink);

            collector.Observe();
            Assert.Equal(1, collector.Of("freesftpsharp.connections.active").Last().Value);
        }

        await _server.Sink.WaitForAsync<FileEvent>(e => e.Type == FileEventType.Download && e.VirtualPath == path);
        // The metrics sink has its own queue; give it the same time as the recording sink.
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (collector.Sum("freesftpsharp.transfers", ("direction", "download")) < 1 && DateTime.UtcNow < deadline)
            await Task.Delay(10, TestContext.Current.CancellationToken);

        Assert.Equal(1, collector.Sum("freesftpsharp.transfers", ("direction", "upload"), ("status", "ok"), ("protocol", "SFTP")));
        Assert.Equal(data.Length, collector.Sum("freesftpsharp.transfer.bytes", ("direction", "upload"), ("protocol", "SFTP")));
        Assert.Equal(1, collector.Sum("freesftpsharp.transfers", ("direction", "download"), ("status", "ok")));
        Assert.Equal(data.Length, collector.Sum("freesftpsharp.transfer.bytes", ("direction", "download")));
        Assert.Equal(1, collector.Sum("freesftpsharp.auth.attempts", ("method", "password"), ("result", "ok")));
    }
}
