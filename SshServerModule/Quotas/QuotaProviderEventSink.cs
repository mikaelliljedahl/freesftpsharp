#nullable enable
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Quotas;

namespace SshServerModule.Quotas
{
    /// <summary>
    /// Keeps the quota counters in step with the users and folders (issue #62), from the provider events of the settings
    /// repository, whoever made the change (admin UI, command line, later the REST API): a removed user or folder loses its
    /// counters, and a new user, or a user whose quota or storage changed, gets a scan of its scopes with a quota (the
    /// counters were not kept while the scope had no quota).
    /// </summary>
    public sealed class QuotaProviderEventSink : IEventSink
    {
        private static readonly string[] RescanFields =
        [
            nameof(UserSnapshot.DiskQuota), nameof(UserSnapshot.VirtualFolders), nameof(UserSnapshot.StorageProvider),
            nameof(UserSnapshot.UserRootDirectory),
        ];

        private readonly QuotaUsageTracker _tracker;
        private readonly QuotaScanQueue _scans;

        /// <remarks>It does not use the settings repository: the repository publishes on the event bus, which holds this sink.</remarks>
        public QuotaProviderEventSink(QuotaUsageTracker tracker, QuotaScanQueue scans)
        {
            _tracker = tracker;
            _scans = scans;
        }

        public async ValueTask HandleAsync(IEvent @event, CancellationToken ct)
        {
            if (@event is not ProviderEvent change)
                return;
            switch (change.ObjectType, change.Action)
            {
                case (ProviderObjectType.User, ProviderAction.Delete):
                    await _tracker.RemoveAsync(QuotaScope.ForUser(change.ObjectName), ct);
                    break;
                case (ProviderObjectType.VirtualFolder, ProviderAction.Delete) when change.Object is VirtualFolderSnapshot folder:
                    await _tracker.RemoveAsync(QuotaScope.ForFolder(folder.Id), ct);
                    break;
                case (ProviderObjectType.VirtualFolder, ProviderAction.Update) when change.Object is VirtualFolderSnapshot folder
                                                                                  && (change.ChangedFields ?? []).Any(f => f is "Storage" or nameof(VirtualFolderSnapshot.StorageProvider)):
                    _scans.Request(QuotaScope.ForFolder(folder.Id));
                    break;
                case (ProviderObjectType.User, ProviderAction.Add):
                case (ProviderObjectType.User, ProviderAction.Update) when (change.ChangedFields ?? []).Any(f => Array.IndexOf(RescanFields, f) >= 0):
                    _scans.RequestUser(change.ObjectName);
                    break;
            }
        }
    }
}
