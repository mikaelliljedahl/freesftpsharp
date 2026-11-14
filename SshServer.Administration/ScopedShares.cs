using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Shares;

namespace SshServer.Administration
{
    /// <summary>A share link (#70) for the administrators: everything except the password hash.</summary>
    public sealed record ShareView(string Id, string Username, string Name, string Description, IReadOnlyList<string> Paths,
        ShareScope Scope, bool AllowOverwrite, bool HasPassword, DateTime? ExpiresAt, int MaxUses, int UsedCount,
        IReadOnlyList<string> AllowedIps, DateTime CreatedAt, DateTime? LastUsedAt)
    {
        public static ShareView From(Share share) => new(share.Id, share.Username, share.Name, share.Description, share.Paths.ToList(),
            share.Scope, share.AllowOverwrite, share.HasPassword, share.ExpiresAt, share.MaxUses, share.UsedCount,
            share.AllowedIps?.ToList() ?? [], share.CreatedAt, share.LastUsedAt);
    }

    /// <summary>
    /// The share links of the users (#70) as the signed-in administrator may see them (scoped per circuit or API request):
    /// listing and revoking need <see cref="AdminPermissions.ManageUsers"/>. An administrator with a scope role sees and
    /// revokes only the shares of the users of its role; the others are "not found".
    /// </summary>
    public sealed class ScopedShares
    {
        private readonly IShareStore _store;
        private readonly CurrentAdmin _current;
        private readonly AdminScopedSettingsRepository _scope;
        private readonly ILogger<ScopedShares> _logger;

        public ScopedShares(IShareStore store, CurrentAdmin current, AdminScopedSettingsRepository scope, ILogger<ScopedShares> logger)
        {
            _store = store;
            _current = current;
            _scope = scope;
            _logger = logger;
        }

        /// <summary>The shares, newest first; of one user when <paramref name="username"/> is given.</summary>
        public async Task<IReadOnlyList<ShareView>> ListAsync(string username, CancellationToken ct)
        {
            _current.Actor.Demand(AdminPermissions.ManageUsers);
            var usernames = _scope.UsernamesInScope();
            var all = await _store.ListAsync(null, ct);
            return all.Where(s => Visible(s, usernames) && (username == null || string.Equals(s.Username, username, StringComparison.OrdinalIgnoreCase)))
                .Select(ShareView.From).ToList();
        }

        /// <summary>Removes a share: its link stops working at once. False when it does not exist or is not in the scope.</summary>
        public async Task<bool> RevokeAsync(string id, CancellationToken ct)
        {
            _current.Actor.Demand(AdminPermissions.ManageUsers);
            if (!ShareId.IsWellFormed(id))
                return false;
            var share = await _store.GetAsync(id, ct);
            if (share == null || !Visible(share, _scope.UsernamesInScope()))
                return false;
            if (!await _store.RemoveAsync(id, ct))
                return false;
            _logger.LogInformation("The administrator {Admin} revoked the share {ShareId} of {Username}.", _current.Actor.AuditName, id, share.Username);
            return true;
        }

        private static bool Visible(Share share, IReadOnlySet<string> usernames) => usernames == null || usernames.Contains(share.Username);
    }
}
