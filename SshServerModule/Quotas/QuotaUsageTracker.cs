#nullable enable
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Interfaces.Quotas;

namespace SshServerModule.Quotas
{
    /// <summary>
    /// The quota counters in memory (issue #62), over the shared <see cref="IQuotaUsageStore"/>. The storage decorators
    /// check and change the counters here, synchronously and without a database call; the changes are written to the
    /// store as increments by <see cref="FlushAsync"/> (every few seconds, <see cref="QuotaUsageFlushService"/>), and each
    /// write gives the stored value back, so the counters of other nodes come in too. A scope is loaded once per session
    /// open (<see cref="LoadAsync"/>) and read again from the store when it had no change for <see cref="RefreshAfter"/>.
    /// The counters are approximate (as in SFTPGo): a scan (<see cref="QuotaScanService"/>) sets the real disk usage.
    /// </summary>
    public sealed class QuotaUsageTracker
    {
        /// <summary>A loaded scope without own changes is read again from the store after this time.</summary>
        public static readonly TimeSpan RefreshAfter = TimeSpan.FromSeconds(30);

        private readonly IQuotaUsageStore _store;
        private readonly TimeProvider _time;
        private readonly ILogger _logger;
        private readonly ConcurrentDictionary<QuotaScope, Entry> _entries = new();
        private readonly SemaphoreSlim _write = new(1, 1); // one store write at a time, so a flush, a scan and a load never overtake each other

        public QuotaUsageTracker(IQuotaUsageStore store, TimeProvider? time = null, ILogger<QuotaUsageTracker>? logger = null)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _time = time ?? TimeProvider.System;
            _logger = (ILogger?)logger ?? NullLogger.Instance;
        }

        /// <summary>Loads the counters of a scope from the store (again, when they are older than <see cref="RefreshAfter"/> and unchanged), and returns them.</summary>
        /// <param name="diskQuota">True when the scope has a disk quota: <see cref="DiskScopes"/> lists it.</param>
        public async ValueTask<QuotaUsage> LoadAsync(QuotaScope scope, CancellationToken ct, bool diskQuota = false)
        {
            var entry = _entries.GetOrAdd(scope, _ => new Entry());
            if (diskQuota)
                entry.HasDiskQuota = true;
            if (!entry.NeedsLoad(_time.GetUtcNow()))
                return entry.Current;

            await _write.WaitAsync(ct);
            try
            {
                if (entry.NeedsLoad(_time.GetUtcNow()))
                    entry.SetStored(await _store.GetAsync(scope, ct) ?? QuotaUsage.Empty, _time.GetUtcNow());
            }
            finally
            {
                _write.Release();
            }
            return entry.Current;
        }

        /// <summary>The counters as this node knows them; <see cref="QuotaUsage.Empty"/> for a scope that was never loaded.</summary>
        public QuotaUsage Current(QuotaScope scope) => _entries.TryGetValue(scope, out var entry) ? entry.Current : QuotaUsage.Empty;

        /// <summary>The loaded scopes with a disk quota and their counters (for the metrics).</summary>
        public IReadOnlyList<KeyValuePair<QuotaScope, QuotaUsage>> DiskScopes()
            => _entries.Where(e => e.Value.IsLoaded && e.Value.HasDiskQuota).Select(e => new KeyValuePair<QuotaScope, QuotaUsage>(e.Key, e.Value.Current)).ToList();

        /// <summary>
        /// Adds <paramref name="bytes"/> and <paramref name="files"/> (not negative) to the disk counters when the result stays
        /// within <paramref name="limit"/>; returns false, and changes nothing, when it would not.
        /// </summary>
        public bool TryReserveDisk(QuotaScope scope, DiskQuota limit, long bytes, long files)
            => EntryOf(scope).TryAdd(new QuotaUsageDelta(bytes, files, 0, 0), usage =>
                (limit.MaxSizeBytes <= 0 || bytes <= 0 || usage.UsedBytes + bytes <= limit.MaxSizeBytes)
                && (limit.MaxFiles <= 0 || files <= 0 || usage.UsedFiles + files <= limit.MaxFiles));

        /// <summary>Changes the disk counters without a check (a release is negative).</summary>
        public void AddDisk(QuotaScope scope, long bytes, long files)
        {
            if (bytes != 0 || files != 0)
                EntryOf(scope).Add(new QuotaUsageDelta(bytes, files, 0, 0));
        }

        /// <summary>Counts an upload of <paramref name="bytes"/> when it stays within <paramref name="limit"/>; false, and nothing counted, when it would not.</summary>
        public bool TryAddUpload(QuotaScope scope, TransferQuota limit, long bytes)
            => EntryOf(scope).TryAdd(new QuotaUsageDelta(0, 0, bytes, 0), usage =>
                (limit.MaxUploadBytes <= 0 || usage.UploadedBytes + bytes <= limit.MaxUploadBytes)
                && (limit.MaxTotalBytes <= 0 || usage.UploadedBytes + usage.DownloadedBytes + bytes <= limit.MaxTotalBytes));

        /// <summary>How many bytes the user may still download (<see cref="long.MaxValue"/>: unlimited).</summary>
        public long DownloadAllowance(QuotaScope scope, TransferQuota limit)
        {
            var usage = Current(scope);
            var allowance = long.MaxValue;
            if (limit.MaxDownloadBytes > 0)
                allowance = Math.Min(allowance, limit.MaxDownloadBytes - usage.DownloadedBytes);
            if (limit.MaxTotalBytes > 0)
                allowance = Math.Min(allowance, limit.MaxTotalBytes - usage.UploadedBytes - usage.DownloadedBytes);
            return Math.Max(0, allowance);
        }

        /// <summary>Changes the transfer counters without a check (a refund is negative).</summary>
        public void AddTransfer(QuotaScope scope, long uploaded, long downloaded)
        {
            if (uploaded != 0 || downloaded != 0)
                EntryOf(scope).Add(new QuotaUsageDelta(0, 0, uploaded, downloaded));
        }

        /// <summary>Writes the changes of every scope to the store. A failed write is kept for the next flush.</summary>
        public async Task FlushAsync(CancellationToken ct)
        {
            await _write.WaitAsync(ct);
            try
            {
                foreach (var (scope, entry) in _entries)
                {
                    var delta = entry.BeginFlush();
                    if (delta.IsZero)
                        continue;
                    try
                    {
                        entry.EndFlush(await _store.AddAsync(scope, delta, _time.GetUtcNow(), ct), _time.GetUtcNow());
                    }
                    catch (Exception ex)
                    {
                        entry.FailFlush();
                        if (ex is OperationCanceledException && ct.IsCancellationRequested)
                            throw;
                        _logger.LogWarning(ex, "Could not save the quota usage of {Scope}; it is saved with the next flush.", scope);
                    }
                }
            }
            finally
            {
                _write.Release();
            }
        }

        /// <summary>Sets the disk counters to the result of a scan; the changes since the last flush are dropped (the scan has them).</summary>
        public async Task<QuotaUsage> SetDiskUsageAsync(QuotaScope scope, long usedBytes, long usedFiles, CancellationToken ct)
        {
            await _write.WaitAsync(ct);
            try
            {
                var stored = await _store.SetDiskUsageAsync(scope, usedBytes, usedFiles, _time.GetUtcNow(), ct);
                var entry = EntryOf(scope);
                entry.SetStored(stored, _time.GetUtcNow(), dropPending: p => p with { Bytes = 0, Files = 0 });
                return entry.Current;
            }
            finally
            {
                _write.Release();
            }
        }

        /// <summary>Sets the transfer counters to 0.</summary>
        public async Task<QuotaUsage> ResetTransferAsync(QuotaScope scope, CancellationToken ct)
        {
            await _write.WaitAsync(ct);
            try
            {
                var stored = await _store.ResetTransferAsync(scope, _time.GetUtcNow(), ct);
                var entry = EntryOf(scope);
                entry.SetStored(stored, _time.GetUtcNow(), dropPending: p => p with { Uploaded = 0, Downloaded = 0 });
                return entry.Current;
            }
            finally
            {
                _write.Release();
            }
        }

        /// <summary>Removes the counters of a removed user or folder, in memory and in the store.</summary>
        public async Task RemoveAsync(QuotaScope scope, CancellationToken ct)
        {
            await _write.WaitAsync(ct);
            try
            {
                _entries.TryRemove(scope, out _);
                await _store.RemoveAsync(scope, ct);
            }
            finally
            {
                _write.Release();
            }
        }

        private Entry EntryOf(QuotaScope scope) => _entries.GetOrAdd(scope, _ => new Entry());

        /// <summary>
        /// The counters of one scope: the stored value, the change that is being written (in flight) and the change that is
        /// not written yet. The current value is their sum, so a flush never hides a change from a check.
        /// </summary>
        private sealed class Entry
        {
            private readonly object _lock = new();
            private QuotaUsage _stored = QuotaUsage.Empty;
            private QuotaUsageDelta _inFlight;
            private QuotaUsageDelta _pending;
            private DateTimeOffset _loadedAt;
            private bool _loaded;

            public bool HasDiskQuota { get; set; }

            public bool IsLoaded
            {
                get { lock (_lock) return _loaded; }
            }

            public QuotaUsage Current
            {
                get { lock (_lock) return _stored.Add(_inFlight + _pending); }
            }

            public bool NeedsLoad(DateTimeOffset now)
            {
                lock (_lock)
                    return !_loaded || (_pending.IsZero && _inFlight.IsZero && now - _loadedAt > RefreshAfter);
            }

            public void SetStored(QuotaUsage stored, DateTimeOffset now, Func<QuotaUsageDelta, QuotaUsageDelta>? dropPending = null)
            {
                lock (_lock)
                {
                    _stored = stored;
                    if (dropPending != null)
                        _pending = dropPending(_pending);
                    _loaded = true;
                    _loadedAt = now;
                }
            }

            public bool TryAdd(QuotaUsageDelta delta, Func<QuotaUsage, bool> allowed)
            {
                lock (_lock)
                {
                    if (!allowed(_stored.Add(_inFlight + _pending)))
                        return false;
                    _pending += delta;
                    return true;
                }
            }

            public void Add(QuotaUsageDelta delta)
            {
                lock (_lock)
                    _pending += delta;
            }

            public QuotaUsageDelta BeginFlush()
            {
                lock (_lock)
                {
                    _inFlight = _pending;
                    _pending = default;
                    return _inFlight;
                }
            }

            public void EndFlush(QuotaUsage stored, DateTimeOffset now)
            {
                lock (_lock)
                {
                    _stored = stored; // it has the in-flight change, and the changes of other nodes
                    _inFlight = default;
                    _loaded = true;
                    _loadedAt = now;
                }
            }

            public void FailFlush()
            {
                lock (_lock)
                {
                    _pending += _inFlight;
                    _inFlight = default;
                }
            }
        }
    }
}
