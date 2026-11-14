using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces.Quotas;
using SshServerModule.Connections;
using SshServerModule.Observability;
using SshServerModule.Quotas;

namespace FreeSftpSharp.Tests.Observability;

/// <summary>The quota gauges (issue #62): only the scopes with a disk quota, by scope.</summary>
public sealed class QuotaMetricsTests
{
    [Fact]
    public async Task The_usage_of_each_scope_with_a_disk_quota_is_a_gauge()
    {
        var ct = TestContext.Current.CancellationToken;
        var tracker = new QuotaUsageTracker(new InMemoryQuotaUsageStore());
        using var metrics = new FreeSftpSharpMetrics(new ConnectionRegistry(new FakeTimeProvider()), tracker);
        using var collector = new MeasurementCollector(metrics.Meter);
        await tracker.LoadAsync(QuotaScope.ForUser("alice"), ct, diskQuota: true);
        await tracker.LoadAsync(QuotaScope.ForUser("transfer-only"), ct); // no disk quota: no series
        tracker.AddDisk(QuotaScope.ForUser("alice"), 4096, 2);
        tracker.AddDisk(QuotaScope.ForUser("transfer-only"), 1, 1);

        collector.Observe();

        Assert.Equal(4096, collector.Sum("freesftpsharp.quota.usage", ("scope", "user:alice")));
        Assert.Equal(2, collector.Sum("freesftpsharp.quota.files", ("scope", "user:alice")));
        Assert.Single(collector.Of("freesftpsharp.quota.usage"));
    }
}
