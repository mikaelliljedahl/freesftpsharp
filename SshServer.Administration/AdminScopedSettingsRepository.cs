using System;
using System.Collections.Generic;
using System.Linq;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Storage;

namespace SshServer.Administration
{
    /// <summary>
    /// The settings repository as the signed-in administrator may use it (scoped per circuit). The admin pages use it
    /// instead of the shared <see cref="ISettingsRepository"/>:
    /// <list type="bullet">
    /// <item>Users need <see cref="AdminPermissions.ManageUsers"/>. Without it no user is visible and a change throws
    /// <see cref="AdminAccessDeniedException"/>.</item>
    /// <item>An administrator with a scope role sees only the users of its role: another user is "not found" for it,
    /// also by name. A new user gets its role; it cannot create a user without a role or with another role, and it
    /// cannot move a user to another role.</item>
    /// <item>A change of the server settings needs <see cref="AdminPermissions.ManageSettings"/>.</item>
    /// </list>
    /// </summary>
    public sealed class AdminScopedSettingsRepository : ISettingsRepository
    {
        private readonly ISettingsRepository _inner;
        private readonly CurrentAdmin _current;

        public AdminScopedSettingsRepository(ISettingsRepository inner, CurrentAdmin current)
        {
            _inner = inner;
            _current = current;
        }

        /// <summary>Every signed-in administrator may read the settings (the dashboard shows them).</summary>
        public ServerSettings ServerSettings
        {
            get
            {
                DemandSignedIn(_current.Actor);
                return _inner.ServerSettings;
            }
        }

        public bool UpdateServerSettings(ServerSettings updatedSettings)
        {
            _current.Actor.Demand(AdminPermissions.ManageSettings);
            return _inner.UpdateServerSettings(updatedSettings);
        }

        /// <summary>The user, or null when there is none or it is not visible to the administrator.</summary>
        public User GetUser(string username)
        {
            var actor = _current.Actor;
            if (!actor.Has(AdminPermissions.ManageUsers))
                return null;
            var user = _inner.GetUser(username);
            return actor.CanSee(user) ? user : null;
        }

        public List<User> GetAllUsers()
        {
            var actor = _current.Actor;
            return actor.Has(AdminPermissions.ManageUsers) ? _inner.GetAllUsers().Where(actor.CanSee).ToList() : new List<User>();
        }

        public bool AddUser(User newUser)
        {
            var actor = _current.Actor;
            actor.Demand(AdminPermissions.ManageUsers);
            if (actor.ScopeRoleId is { } scope)
            {
                newUser.RoleId ??= scope;
                if (newUser.RoleId != scope)
                    throw new AdminAccessDeniedException("You can only create users with your own role.");
            }
            return _inner.AddUser(newUser);
        }

        public bool UpdateUser(User updatedUser)
        {
            var actor = _current.Actor;
            actor.Demand(AdminPermissions.ManageUsers);
            var stored = _inner.GetUser(updatedUser.Username);
            if (!actor.CanSee(stored))
                return false;
            if (actor.ScopeRoleId != null)
                updatedUser.RoleId = stored.RoleId;
            return _inner.UpdateUser(updatedUser);
        }

        public bool RemoveUser(string username)
        {
            var actor = _current.Actor;
            actor.Demand(AdminPermissions.ManageUsers);
            return actor.CanSee(_inner.GetUser(username)) && _inner.RemoveUser(username);
        }

        /// <summary>
        /// The virtual folders (#56) are not scoped: an administrator who manages users may see them (to mount them), and
        /// one with <see cref="AdminPermissions.ManageFolders"/> may change them.
        /// </summary>
        public List<VirtualFolder> GetVirtualFolders()
        {
            var actor = _current.Actor;
            return actor.Has(AdminPermissions.ManageFolders) || actor.Has(AdminPermissions.ManageUsers) ? _inner.GetVirtualFolders() : new List<VirtualFolder>();
        }

        public VirtualFolder GetVirtualFolder(int id)
        {
            var actor = _current.Actor;
            return actor.Has(AdminPermissions.ManageFolders) || actor.Has(AdminPermissions.ManageUsers) ? _inner.GetVirtualFolder(id) : null;
        }

        public bool AddVirtualFolder(VirtualFolder folder)
        {
            _current.Actor.Demand(AdminPermissions.ManageFolders);
            return _inner.AddVirtualFolder(folder);
        }

        public bool UpdateVirtualFolder(VirtualFolder folder)
        {
            _current.Actor.Demand(AdminPermissions.ManageFolders);
            return _inner.UpdateVirtualFolder(folder);
        }

        public bool RemoveVirtualFolder(int id)
        {
            _current.Actor.Demand(AdminPermissions.ManageFolders);
            return _inner.RemoveVirtualFolder(id);
        }

        /// <summary>
        /// The names of the users in the scope of the administrator (for the connections and the audit log), or null
        /// when it has no scope (everything). Needs no <see cref="AdminPermissions.ManageUsers"/>.
        /// </summary>
        public IReadOnlySet<string> UsernamesInScope()
        {
            var actor = _current.Actor;
            DemandSignedIn(actor);
            if (actor.ScopeRoleId == null)
                return null;
            return _inner.GetAllUsers().Where(actor.CanSee).Select(u => u.Username).ToHashSet(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>The shared repository is a singleton; this view releases nothing.</summary>
        public void Dispose()
        {
        }

        private static void DemandSignedIn(AdminActor actor)
        {
            if (string.IsNullOrEmpty(actor.Username))
                throw new AdminAccessDeniedException("You are not logged in.");
        }
    }
}
