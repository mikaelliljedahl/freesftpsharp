using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Audit;

namespace SshServer.Administration
{
    /// <summary>
    /// The audit log as the signed-in administrator may read it (scoped per circuit): it needs
    /// <see cref="AdminPermissions.ViewAudit"/>, and an administrator with a scope role reads only the entries of the
    /// users of its role.
    /// </summary>
    public sealed class ScopedAuditLog
    {
        private readonly IAuditLog _inner;
        private readonly CurrentAdmin _current;
        private readonly AdminScopedSettingsRepository _scope;

        public ScopedAuditLog(IAuditLog inner, CurrentAdmin current, AdminScopedSettingsRepository scope)
        {
            _inner = inner;
            _current = current;
            _scope = scope;
        }

        public bool IsEnabled => _inner.IsEnabled;

        public Task<AuditQueryResult> QueryAsync(AuditQuery query, CancellationToken ct)
        {
            _current.Actor.Demand(AdminPermissions.ViewAudit);
            var usernames = _scope.UsernamesInScope();
            if (usernames != null)
            {
                var allowed = query.Usernames == null ? usernames.ToList() : query.Usernames.Where(usernames.Contains).ToList();
                query = query with { Usernames = allowed };
            }
            return _inner.QueryAsync(query, ct);
        }
    }
}
