#nullable enable
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces;
using SshServer.Interfaces.Quotas;

namespace SshServerModule.Quotas
{
    /// <summary>The usage of one quota scope of a user, for the admin UI.</summary>
    /// <param name="Label">"/" for the own storage, else the mount path and the folder name.</param>
    /// <param name="Limit">The disk quota.</param>
    /// <param name="ScanQueued">True while a scan of the scope waits in the queue.</param>
    public sealed record QuotaScopeView(QuotaScope Scope, string Label, DiskQuota Limit, QuotaUsage Usage, bool ScanQueued);

    /// <summary>The quotas of a user with their usage: the scopes with a disk quota, and the transfer counters.</summary>
    /// <param name="Transfer">The transfer quota; null: unlimited (the counters are then not kept).</param>
    public sealed record UserQuotaView(IReadOnlyList<QuotaScopeView> Disk, TransferQuota? Transfer, QuotaUsage TransferUsage)
    {
        public bool IsEmpty => Disk.Count == 0 && Transfer is null;
    }

    /// <summary>
    /// The application service of the quota counters (issue #62) for the admin UI (and later the REST API, #67): the usage
    /// of a user, a rescan, and the reset of the transfer counters. It finds the user through the repository it gets (the
    /// admin UI passes its scoped view), so an administrator reaches only the users it may see.
    /// </summary>
    public sealed class QuotaAdministrationService
    {
        private readonly ISettingsRepository _repository;
        private readonly IEffectiveQuotaService _quotas;
        private readonly QuotaUsageTracker _tracker;
        private readonly QuotaScanQueue _scans;

        public QuotaAdministrationService(ISettingsRepository repository, IEffectiveQuotaService quotas, QuotaUsageTracker tracker, QuotaScanQueue scans)
        {
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));
            _quotas = quotas ?? throw new ArgumentNullException(nameof(quotas));
            _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
            _scans = scans ?? throw new ArgumentNullException(nameof(scans));
        }

        /// <summary>The quotas and usage of the user, or null when there is no such user (or it is not visible).</summary>
        public async Task<UserQuotaView?> GetAsync(string username, CancellationToken ct)
        {
            var user = _repository.GetUser(username);
            if (user is null)
                return null;
            var quotas = _quotas.Resolve(user);
            var disk = new List<QuotaScopeView>();
            var userQueued = _scans.IsUserPending(user.Username);
            if (quotas.Disk is { } own)
                disk.Add(await ViewAsync(QuotaScope.ForUser(user.Username), "/", own, userQueued, ct));
            foreach (var mount in user.VirtualFolders ?? [])
            {
                if (quotas.ForMount(mount.MountPath) is not { } limit)
                    continue;
                var name = _repository.GetVirtualFolder(mount.VirtualFolderId)?.Name ?? $"folder {mount.VirtualFolderId}";
                disk.Add(await ViewAsync(QuotaScope.ForFolder(mount.VirtualFolderId), $"{mount.MountPath} ({name})", limit, userQueued, ct));
            }
            var transfer = quotas.Transfer is null ? QuotaUsage.Empty : await _tracker.LoadAsync(QuotaScope.ForUser(user.Username), ct);
            return new UserQuotaView(disk, quotas.Transfer, transfer);
        }

        /// <summary>Queues a scan of every scope with a disk quota of the user. False when there is no such user.</summary>
        public bool RequestScan(string username)
        {
            var user = _repository.GetUser(username);
            if (user is null)
                return false;
            _scans.RequestUser(user.Username);
            return true;
        }

        /// <summary>Sets the uploaded and downloaded bytes of the user to 0. False when there is no such user.</summary>
        public async Task<bool> ResetTransferAsync(string username, CancellationToken ct)
        {
            var user = _repository.GetUser(username);
            if (user is null)
                return false;
            await _tracker.ResetTransferAsync(QuotaScope.ForUser(user.Username), ct);
            return true;
        }

        private async Task<QuotaScopeView> ViewAsync(QuotaScope scope, string label, DiskQuota limit, bool userQueued, CancellationToken ct)
            => new(scope, label, limit, await _tracker.LoadAsync(scope, ct), userQueued || _scans.IsPending(scope));
    }
}
