#nullable enable
using System;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Quotas
{
    /// <summary>
    /// Adds the quota decorators of a user to the chain of <see cref="Storage.StorageFileSystemFactory"/> (issue #62): a
    /// <see cref="DiskQuotaFileSystem"/> around each storage with a disk quota, and around the whole session a
    /// <see cref="TransferQuotaFileSystem"/> and a <see cref="BandwidthFileSystem"/>. Each is left out when its limit is
    /// not set, so a user without a quota gets no decorator and no counter.
    /// </summary>
    public sealed class QuotaDecorators
    {
        private readonly IEffectiveQuotaService _quotas;
        private readonly QuotaUsageTracker _tracker;
        private readonly QuotaScanQueue? _scans;
        private readonly TimeProvider _time;

        /// <param name="scans">Queues the scan of a scope that was never scanned at its first session. Null: no automatic scan.</param>
        /// <param name="time">The clock of the bandwidth limits. Null: the system clock.</param>
        public QuotaDecorators(IEffectiveQuotaService quotas, QuotaUsageTracker tracker, QuotaScanQueue? scans = null, TimeProvider? time = null)
        {
            _quotas = quotas ?? throw new ArgumentNullException(nameof(quotas));
            _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
            _scans = scans;
            _time = time ?? TimeProvider.System;
        }

        public EffectiveQuotas Resolve(User user) => _quotas.Resolve(user);

        /// <summary>One storage (the own storage of the user or a virtual folder) with its disk quota.</summary>
        public async ValueTask<IFileSystem> WrapStorageAsync(IFileSystem storage, QuotaScope scope, DiskQuota? limit, CancellationToken ct)
        {
            if (DiskQuota.OrNull(limit) is not { } quota)
                return storage;
            var usage = await _tracker.LoadAsync(scope, ct, diskQuota: true);
            if (usage.ScannedAt is null)
                _scans?.Request(scope);
            return new DiskQuotaFileSystem(storage, _tracker, scope, quota);
        }

        /// <summary>The whole file system of a session with the transfer quota and the bandwidth of the user for this client.</summary>
        public async ValueTask<IFileSystem> WrapSessionAsync(IFileSystem fileSystem, User user, EffectiveQuotas quotas, ClientContext client, CancellationToken ct)
        {
            if (quotas.Transfer is { } transfer)
            {
                var scope = QuotaScope.ForUser(user.Username);
                await _tracker.LoadAsync(scope, ct);
                fileSystem = new TransferQuotaFileSystem(fileSystem, _tracker, scope, transfer);
            }
            if (quotas.Bandwidth is { } bandwidth)
            {
                var (upload, download) = bandwidth.For(client.RemoteIp);
                fileSystem = BandwidthFileSystem.Wrap(fileSystem, upload, download, _time);
            }
            return fileSystem;
        }
    }
}
