using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Connections;

namespace FxSshSftpServer.Security
{
    /// <summary>
    /// The open connections as the signed-in administrator may see them (scoped per circuit): listing needs
    /// <see cref="AdminPermissions.ViewConnections"/>, closing one <see cref="AdminPermissions.DisconnectConnections"/>.
    /// An administrator with a scope role sees and closes only the connections of the users of its role (a connection
    /// before its login has no user and is not in any scope).
    /// </summary>
    public sealed class ScopedConnections
    {
        private readonly IConnectionRegistry _registry;
        private readonly CurrentAdmin _current;
        private readonly AdminScopedSettingsRepository _scope;

        public ScopedConnections(IConnectionRegistry registry, CurrentAdmin current, AdminScopedSettingsRepository scope)
        {
            _registry = registry;
            _current = current;
            _scope = scope;
        }

        public bool CanDisconnect => _current.Has(AdminPermissions.DisconnectConnections);

        public IReadOnlyList<ConnectionInfo> GetAll()
        {
            _current.Actor.Demand(AdminPermissions.ViewConnections);
            var usernames = _scope.UsernamesInScope();
            var all = _registry.GetAll();
            return usernames == null ? all : all.Where(c => c.Username != null && usernames.Contains(c.Username)).ToList();
        }

        /// <summary>False when the connection is closed already or not visible to the administrator.</summary>
        public Task<bool> DisconnectAsync(Guid id, string reason)
        {
            _current.Actor.Demand(AdminPermissions.DisconnectConnections | AdminPermissions.ViewConnections);
            var connection = _registry.Get(id);
            var usernames = _scope.UsernamesInScope();
            if (connection == null || (usernames != null && (connection.Username == null || !usernames.Contains(connection.Username))))
                return Task.FromResult(false);
            return _registry.DisconnectAsync(id, reason);
        }
    }
}
