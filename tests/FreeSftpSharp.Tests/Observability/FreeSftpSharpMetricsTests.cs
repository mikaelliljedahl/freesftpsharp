using System.Diagnostics;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServerModule.Connections;
using SshServerModule.Observability;

namespace FreeSftpSharp.Tests.Observability;

/// <summary>The counters, gauges and histograms of the server, read with a <c>MeterListener</c>.</summary>
public sealed class FreeSftpSharpMetricsTests : IDisposable
{
    private readonly ConnectionRegistry _registry = new(new FakeTimeProvider());
    private readonly FreeSftpSharpMetrics _metrics;
    private readonly MeasurementCollector _collector;

    public FreeSftpSharpMetricsTests()
    {
        _metrics = new FreeSftpSharpMetrics(_registry);
        _collector = new MeasurementCollector(_metrics.Meter);
    }

    public void Dispose()
    {
        _collector.Dispose();
        _metrics.Dispose();
    }

    private static FileEvent File(FileEventType type, FileEventStatus status = FileEventStatus.Ok, long? size = null, double? seconds = null) => new(type)
    {
        Timestamp = DateTimeOffset.UtcNow, Protocol = "SFTP", Provider = "local", Status = status, FileSize = size,
        Elapsed = seconds is { } s ? TimeSpan.FromSeconds(s) : null, VirtualPath = "/a.bin", Username = "alice",
    };

    private ValueTask Handle(IEvent e) => _metrics.HandleAsync(e, CancellationToken.None);

    [Fact]
    public async Task An_upload_counts_the_transfer_and_the_bytes()
    {
        await Handle(File(FileEventType.Upload, size: 1234, seconds: 0.5));
        await Handle(File(FileEventType.FirstUpload, size: 1234, seconds: 0.5)); // the same upload again, not counted twice

        Assert.Equal(1, _collector.Sum("freesftpsharp.transfers", ("direction", "upload"), ("status", "ok"), ("protocol", "SFTP")));
        Assert.Equal(1234, _collector.Sum("freesftpsharp.transfer.bytes", ("direction", "upload"), ("protocol", "SFTP")));
        Assert.Equal(0.5, _collector.Sum("freesftpsharp.transfer.duration", ("direction", "upload")));
        Assert.Equal(0.5 * 2 - 0.5, _collector.Sum("freesftpsharp.storage.operation.duration", ("operation", "upload"), ("provider", "local")), 3);
    }

    [Fact]
    public async Task A_download_is_counted_by_direction()
    {
        await Handle(File(FileEventType.Download, size: 10));

        Assert.Equal(1, _collector.Sum("freesftpsharp.transfers", ("direction", "download"), ("status", "ok")));
        Assert.Equal(10, _collector.Sum("freesftpsharp.transfer.bytes", ("direction", "download")));
        Assert.Equal(0, _collector.Sum("freesftpsharp.transfer.bytes", ("direction", "upload")));
    }

    [Fact]
    public async Task A_failed_transfer_counts_with_its_status_but_adds_no_bytes_and_one_storage_error()
    {
        await Handle(File(FileEventType.Upload, FileEventStatus.Error, size: 500, seconds: 0.1));
        await Handle(File(FileEventType.Upload, FileEventStatus.QuotaExceeded, size: 500));

        Assert.Equal(1, _collector.Sum("freesftpsharp.transfers", ("direction", "upload"), ("status", "error")));
        Assert.Equal(1, _collector.Sum("freesftpsharp.transfers", ("direction", "upload"), ("status", "quotaexceeded")));
        Assert.Equal(0, _collector.Sum("freesftpsharp.transfer.bytes"));
        Assert.Equal(1, _collector.Sum("freesftpsharp.storage.errors", ("provider", "local"), ("error", "error")));
        Assert.Equal(1, _collector.Sum("freesftpsharp.storage.errors", ("error", "quotaexceeded")));
    }

    [Fact]
    public async Task A_pre_event_and_a_denied_operation_are_not_counted()
    {
        await Handle(File(FileEventType.PreUpload));
        await Handle(File(FileEventType.Upload, FileEventStatus.Denied));

        Assert.Empty(_collector.Of("freesftpsharp.transfers"));
    }

    [Fact]
    public async Task Other_file_operations_only_feed_the_storage_instruments()
    {
        await Handle(File(FileEventType.Delete, seconds: 0.01));
        await Handle(File(FileEventType.Mkdir, FileEventStatus.Error));

        Assert.Empty(_collector.Of("freesftpsharp.transfers"));
        Assert.Equal(0.01, _collector.Sum("freesftpsharp.storage.operation.duration", ("operation", "delete")), 3);
        Assert.Equal(1, _collector.Sum("freesftpsharp.storage.errors", ("provider", "local")));
    }

    [Fact]
    public async Task Logins_count_by_method_and_result()
    {
        await Handle(new AuthEvent(AuthEventType.LoginOk) { Method = "password", Protocol = "SSH" });
        await Handle(new AuthEvent(AuthEventType.LoginFailed) { Method = "password", Protocol = "SSH" });
        await Handle(new AuthEvent(AuthEventType.LoginFailed) { Method = "publickey", Protocol = "SSH" });
        await Handle(new AuthEvent(AuthEventType.Logout) { Method = "password", Protocol = "SSH" });

        Assert.Equal(1, _collector.Sum("freesftpsharp.auth.attempts", ("method", "password"), ("result", "ok")));
        Assert.Equal(1, _collector.Sum("freesftpsharp.auth.attempts", ("method", "password"), ("result", "failed")));
        Assert.Equal(1, _collector.Sum("freesftpsharp.auth.attempts", ("method", "publickey"), ("result", "failed")));
        Assert.Equal(3, _collector.Of("freesftpsharp.auth.attempts").Count);
    }

    [Fact]
    public void The_connection_gauge_follows_the_registry_and_the_counter_counts_accepted_connections()
    {
        var first = _registry.Register(new ConnectionRegistration(ConnectionProtocols.Sftp, "127.0.0.1:1", _ => Task.CompletedTask));
        _registry.Register(new ConnectionRegistration(ConnectionProtocols.Sftp, "127.0.0.1:2", _ => Task.CompletedTask));
        _collector.Observe();
        Assert.Equal(2, _collector.Of("freesftpsharp.connections.active").Last().Value);
        Assert.Equal(2, _collector.Sum("freesftpsharp.connections", ("protocol", "SFTP")));

        _registry.Unregister(first.Id);
        _collector.Observe();
        Assert.Equal(1, _collector.Of("freesftpsharp.connections.active").Last().Value);
        Assert.Equal(2, _collector.Sum("freesftpsharp.connections", ("protocol", "SFTP")));
    }

    [Fact]
    public void Tracing_makes_an_activity_per_session_and_per_storage_operation_only_when_a_listener_is_there()
    {
        // No listener: nothing happens, nothing throws.
        var quiet = _registry.Register(new ConnectionRegistration(ConnectionProtocols.Sftp, "127.0.0.1:9", _ => Task.CompletedTask));
        _registry.Unregister(quiet.Id);

        var stopped = new List<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == Telemetry.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = stopped.Add,
        };
        ActivitySource.AddActivityListener(listener);

        var connection = _registry.Register(new ConnectionRegistration(ConnectionProtocols.Sftp, "127.0.0.1:10", _ => Task.CompletedTask));
        _metrics.HandleAsync(File(FileEventType.Upload, size: 5, seconds: 0.2) with { SessionId = connection.Id.ToString() }, CancellationToken.None);
        _registry.Unregister(connection.Id);

        var operation = Assert.Single(stopped, a => a.OperationName == "storage.upload");
        var session = Assert.Single(stopped, a => a.OperationName == "sftp.session");
        Assert.Equal(session.SpanId, operation.ParentSpanId);
        Assert.Equal("local", operation.GetTagItem("freesftpsharp.provider"));
        Assert.Equal(TimeSpan.FromSeconds(0.2), operation.Duration);
    }
}
