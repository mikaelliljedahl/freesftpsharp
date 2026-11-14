#nullable enable
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces.Quotas;

namespace SshServerModule.Quotas
{
    /// <summary>
    /// The quota counters in the memory of the process: the store of a server without a settings database (the LiteDB
    /// settings provider, tests). After a restart every scope is "never scanned", so its first session starts a scan.
    /// </summary>
    public sealed class InMemoryQuotaUsageStore : IQuotaUsageStore
    {
        private readonly object _lock = new();
        private readonly Dictionary<QuotaScope, QuotaUsage> _usage = new();

        public Task<QuotaUsage?> GetAsync(QuotaScope scope, CancellationToken ct)
        {
            lock (_lock)
                return Task.FromResult(_usage.TryGetValue(scope, out var usage) ? usage : null);
        }

        public Task<QuotaUsage> AddAsync(QuotaScope scope, QuotaUsageDelta delta, DateTimeOffset now, CancellationToken ct)
            => Change(scope, u => u.Add(delta) with { UpdatedAt = now });

        public Task<QuotaUsage> SetDiskUsageAsync(QuotaScope scope, long usedBytes, long usedFiles, DateTimeOffset scannedAt, CancellationToken ct)
            => Change(scope, u => u with { UsedBytes = usedBytes, UsedFiles = usedFiles, ScannedAt = scannedAt, UpdatedAt = scannedAt });

        public Task<QuotaUsage> ResetTransferAsync(QuotaScope scope, DateTimeOffset now, CancellationToken ct)
            => Change(scope, u => u with { UploadedBytes = 0, DownloadedBytes = 0, UpdatedAt = now });

        public Task RemoveAsync(QuotaScope scope, CancellationToken ct)
        {
            lock (_lock)
                _usage.Remove(scope);
            return Task.CompletedTask;
        }

        private Task<QuotaUsage> Change(QuotaScope scope, Func<QuotaUsage, QuotaUsage> change)
        {
            lock (_lock)
            {
                var updated = change(_usage.TryGetValue(scope, out var usage) ? usage : QuotaUsage.Empty);
                _usage[scope] = updated;
                return Task.FromResult(updated);
            }
        }
    }
}
