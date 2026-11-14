using FreeSftpSharp.Tests.Storage;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;
using SshServerModule.Quotas;

namespace FreeSftpSharp.Tests.Quotas;

/// <summary><see cref="TransferQuotaFileSystem"/>: uploads and downloads are counted and stopped at the limit.</summary>
public sealed class TransferQuotaFileSystemTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly QuotaScope Scope = QuotaScope.ForUser("bob");

    private readonly InMemoryFileSystem _backend = new();
    private readonly QuotaUsageTracker _tracker = new(new InMemoryQuotaUsageStore());

    private IFileSystem Create(TransferQuota quota) => new TransferQuotaFileSystem(_backend, _tracker, Scope, quota);

    private async Task SeedAsync(string path, int size)
    {
        await using var handle = await _backend.OpenAsync(path, FileOpenFlags.Write | FileOpenFlags.Create, null, Ct);
        await handle.WriteAsync(0, new byte[size], Ct);
    }

    [Fact]
    public void Wrap_leaves_out_the_decorator_without_a_limit()
    {
        Assert.Same(_backend, TransferQuotaFileSystem.Wrap(_backend, _tracker, Scope, null));
        Assert.Same(_backend, TransferQuotaFileSystem.Wrap(_backend, _tracker, Scope, new TransferQuota()));
    }

    [Fact]
    public async Task An_upload_over_the_upload_quota_fails()
    {
        var fs = Create(new TransferQuota { MaxUploadBytes = 1_000 });
        await using var handle = await fs.OpenAsync("/up", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct);
        await handle.WriteAsync(0, new byte[600], Ct);

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await handle.WriteAsync(600, new byte[600], Ct));

        Assert.Equal(FileSystemError.QuotaExceeded, ex.Error);
        Assert.Equal(600, _tracker.Current(Scope).UploadedBytes);
        Assert.Equal(600, (await _backend.StatAsync("/up", true, Ct))!.Size);
    }

    [Fact]
    public async Task A_download_gets_what_is_left_and_then_fails_until_the_counters_are_reset()
    {
        await SeedAsync("/down", 1_000);
        var fs = Create(new TransferQuota { MaxDownloadBytes = 700 });
        await using var handle = await fs.OpenAsync("/down", FileOpenFlags.Read, null, Ct);

        Assert.Equal(500, await handle.ReadAsync(0, new byte[500], Ct));
        Assert.Equal(200, await handle.ReadAsync(500, new byte[500], Ct)); // only what is left
        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await handle.ReadAsync(700, new byte[500], Ct));
        Assert.Equal(FileSystemError.QuotaExceeded, ex.Error);
        Assert.Equal(700, _tracker.Current(Scope).DownloadedBytes);

        await _tracker.ResetTransferAsync(Scope, Ct);
        Assert.Equal(300, await handle.ReadAsync(700, new byte[500], Ct));
    }

    [Fact]
    public async Task The_total_quota_counts_both_directions()
    {
        await SeedAsync("/down", 1_000);
        var fs = Create(new TransferQuota { MaxTotalBytes = 1_000 });
        await using (var up = await fs.OpenAsync("/up", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct))
            await up.WriteAsync(0, new byte[800], Ct);

        await using var down = await fs.OpenAsync("/down", FileOpenFlags.Read, null, Ct);
        Assert.Equal(200, await down.ReadAsync(0, new byte[1_000], Ct));
    }
}

/// <summary>The token bucket and the bandwidth decorator, on a <see cref="FakeTimeProvider"/>.</summary>
public sealed class BandwidthTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 11, 1, 12, 0, 0, TimeSpan.Zero));

    [Fact]
    public void The_bucket_starts_full_and_then_makes_each_request_wait_for_its_bytes()
    {
        var bucket = new TokenBucket(1_000, capacity: 500, time: _clock);

        Assert.Equal(TimeSpan.Zero, bucket.Take(500));                   // the capacity goes at once
        Assert.Equal(TimeSpan.FromSeconds(0.25), bucket.Take(250));      // 250 bytes of debt at 1,000 bytes/s
        Assert.Equal(TimeSpan.FromSeconds(1.25), bucket.Take(1_000));    // debt adds up: a request larger than the capacity works

        _clock.Advance(TimeSpan.FromSeconds(1.25));
        Assert.Equal(TimeSpan.FromSeconds(0.1), bucket.Take(100));
    }

    [Fact]
    public void The_bucket_refills_only_up_to_its_capacity()
    {
        var bucket = new TokenBucket(1_000, capacity: 500, time: _clock);
        bucket.Take(500);

        _clock.Advance(TimeSpan.FromHours(1));

        Assert.Equal(TimeSpan.Zero, bucket.Take(500));
        Assert.Equal(TimeSpan.FromSeconds(0.001), bucket.Take(1));
    }

    [Fact]
    public void The_default_capacity_is_a_quarter_second()
    {
        var bucket = new TokenBucket(4_000, time: _clock);

        Assert.Equal(TimeSpan.Zero, bucket.Take(1_000));
        Assert.Equal(TimeSpan.FromSeconds(0.25), bucket.Take(1_000));
    }

    [Fact]
    public async Task WaitAsync_completes_when_the_clock_has_paid_the_debt()
    {
        var bucket = new TokenBucket(1_000, capacity: 100, time: _clock);
        bucket.Take(100);

        var wait = bucket.WaitAsync(500, Ct).AsTask();
        _clock.Advance(TimeSpan.FromSeconds(0.4));
        Assert.False(wait.IsCompleted);
        _clock.Advance(TimeSpan.FromSeconds(0.1));

        await wait.WaitAsync(TimeSpan.FromSeconds(10), Ct);
    }

    [Fact]
    public async Task A_throttled_read_returns_only_after_the_time_of_its_bytes()
    {
        var backend = new InMemoryFileSystem();
        await using (var handle = await backend.OpenAsync("/f", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct))
            await handle.WriteAsync(0, new byte[4_096], Ct);
        var fs = BandwidthFileSystem.Wrap(backend, uploadBytesPerSecond: 0, downloadBytesPerSecond: 1_024, _clock);
        await using var file = await fs.OpenAsync("/f", FileOpenFlags.Read, null, Ct);

        Assert.Equal(256, await file.ReadAsync(0, new byte[256], Ct)); // the capacity (1/4 s)
        var read = file.ReadAsync(256, new byte[1_024], Ct).AsTask();
        _clock.Advance(TimeSpan.FromSeconds(0.9));
        Assert.False(read.IsCompleted);
        _clock.Advance(TimeSpan.FromSeconds(0.1));

        Assert.Equal(1_024, await read.WaitAsync(TimeSpan.FromSeconds(10), Ct));
    }

    [Fact]
    public async Task A_throttled_write_waits_before_it_reaches_the_storage()
    {
        var backend = new InMemoryFileSystem();
        var fs = BandwidthFileSystem.Wrap(backend, uploadBytesPerSecond: 1_000, downloadBytesPerSecond: 0, _clock);
        await using var file = await fs.OpenAsync("/f", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct);
        await file.WriteAsync(0, new byte[250], Ct);

        var write = file.WriteAsync(250, new byte[500], Ct).AsTask();
        Assert.Equal(250, (await backend.StatAsync("/f", true, Ct))!.Size);
        _clock.Advance(TimeSpan.FromSeconds(0.5));

        await write.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        Assert.Equal(750, (await backend.StatAsync("/f", true, Ct))!.Size);
    }

    [Fact]
    public void Wrap_leaves_out_the_decorator_without_a_limit()
    {
        var backend = new InMemoryFileSystem();
        Assert.Same(backend, BandwidthFileSystem.Wrap(backend, 0, 0, _clock));
    }

    [Fact]
    public void A_network_override_replaces_the_limits_of_the_user()
    {
        var limit = new BandwidthLimit
        {
            UploadKiBPerSecond = 100,
            DownloadKiBPerSecond = 200,
            Overrides = [new BandwidthOverride { Sources = ["10.0.0.0/8", "::1"], UploadKiBPerSecond = 0, DownloadKiBPerSecond = 0 }],
        };

        Assert.Equal((100 * 1024L, 200 * 1024L), limit.For("192.0.2.1"));
        Assert.Equal((0L, 0L), limit.For("10.1.2.3"));
        Assert.Equal((0L, 0L), limit.For("::ffff:10.1.2.3"));
        Assert.Equal((0L, 0L), limit.For("::1"));
        Assert.Equal((100 * 1024L, 200 * 1024L), limit.For(null));
        Assert.False(limit.IsUnlimited);
        Assert.True(new BandwidthLimit { Overrides = [new BandwidthOverride { Sources = ["10.0.0.0/8"] }] }.IsUnlimited);
    }
}
