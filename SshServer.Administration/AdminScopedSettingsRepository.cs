using System;
using System.Collections.Generic;
using System.Linq;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Audit;
using SshServer.Interfaces.Groups;
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
    /// <item>Groups (#61) need <see cref="AdminPermissions.ManageGroups"/> to change; an administrator who manages users
    /// may read them (to give them to users). A scoped administrator sees only the groups of its role, creates groups with
    /// its role, and adds or removes only those groups for its users: a group outside its scope stays as it is.</item>
    /// </list>
    /// Every change is made with the administrator as the actor of its provider event (<see cref="AuditActorContext"/>,
    /// #134): its name, and the name of the API key of a REST API call (<see cref="AdminActor.AuditName"/>).
    /// </summary>
    public sealed class AdminScopedSettingsRepository : ISettingsRepository
    {
        private readonly ISettingsRepository _inner;
        private readonly CurrentAdmin _current;
        private readonly AuditActorContext _actors;

        public AdminScopedSettingsRepository(ISettingsRepository inner, CurrentAdmin current, AuditActorContext actors)
        {
            _inner = inner;
            _current = current;
            _actors = actors;
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
            var actor = _current.Actor;
            actor.Demand(AdminPermissions.ManageSettings);
            using (As(actor))
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
            DemandGroupChanges(actor, null, newUser);
            using (As(actor))
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
            DemandGroupChanges(actor, stored, updatedUser);
            using (As(actor))
                return _inner.UpdateUser(updatedUser);
        }

        public bool RemoveUser(string username)
        {
            var actor = _current.Actor;
            actor.Demand(AdminPermissions.ManageUsers);
            if (!actor.CanSee(_inner.GetUser(username)))
                return false;
            using (As(actor))
                return _inner.RemoveUser(username);
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
            var actor = _current.Actor;
            actor.Demand(AdminPermissions.ManageFolders);
            using (As(actor))
                return _inner.AddVirtualFolder(folder);
        }

        public bool UpdateVirtualFolder(VirtualFolder folder)
        {
            var actor = _current.Actor;
            actor.Demand(AdminPermissions.ManageFolders);
            using (As(actor))
                return _inner.UpdateVirtualFolder(folder);
        }

        public bool RemoveVirtualFolder(int id)
        {
            var actor = _current.Actor;
            actor.Demand(AdminPermissions.ManageFolders);
            using (As(actor))
                return _inner.RemoveVirtualFolder(id);
        }

        /// <summary>The groups in the scope of an administrator who manages groups or users.</summary>
        public List<Group> GetGroups()
        {
            var actor = _current.Actor;
            return CanReadGroups(actor) ? _inner.GetGroups().Where(actor.CanSee).ToList() : new List<Group>();
        }

        public Group GetGroup(int id)
        {
            var actor = _current.Actor;
            var group = CanReadGroups(actor) ? _inner.GetGroup(id) : null;
            return actor.CanSee(group) ? group : null;
        }

        public bool AddGroup(Group group)
        {
            var actor = _current.Actor;
            actor.Demand(AdminPermissions.ManageGroups);
            if (actor.ScopeRoleId is { } scope)
            {
                group.RoleId ??= scope;
                if (group.RoleId != scope)
                    throw new AdminAccessDeniedException("You can only create groups with your own role.");
            }
            using (As(actor))
                return _inner.AddGroup(group);
        }

        public bool UpdateGroup(Group group)
        {
            var actor = _current.Actor;
            actor.Demand(AdminPermissions.ManageGroups);
            var stored = _inner.GetGroup(group.Id);
            if (!actor.CanSee(stored))
                return false;
            if (actor.ScopeRoleId != null)
                group.RoleId = stored.RoleId;
            using (As(actor))
                return _inner.UpdateGroup(group);
        }

        public bool RemoveGroup(int id)
        {
            var actor = _current.Actor;
            actor.Demand(AdminPermissions.ManageGroups);
            if (!actor.CanSee(_inner.GetGroup(id)))
                return false;
            using (As(actor))
                return _inner.RemoveGroup(id);
        }

        /// <summary>The actor of the provider events of the inner call.</summary>
        private IDisposable As(AdminActor actor) => _actors.Begin(actor.AuditName);

        private static bool CanReadGroups(AdminActor actor) =>
            actor.Has(AdminPermissions.ManageGroups) || actor.Has(AdminPermissions.ManageUsers);

        /// <summary>
        /// A scoped administrator adds and removes only groups of its scope: a group of another role (or a global one)
        /// could give its users the storage or the permissions of another tenant, or take restrictions away that an
        /// administrator without a scope set. The groups of the user outside the scope must stay as they are.
        /// </summary>
        private void DemandGroupChanges(AdminActor actor, User stored, User updated)
        {
            if (actor.ScopeRoleId == null)
                return;
            var before = GroupIds(stored);
            var after = GroupIds(updated);
            var changed = before.Except(after).Concat(after.Except(before));
            if (stored?.PrimaryGroupId != updated.PrimaryGroupId)
                changed = changed.Concat(new[] { stored?.PrimaryGroupId, updated.PrimaryGroupId }.OfType<int>());
            foreach (var id in changed.Distinct())
            {
                if (!actor.CanSee(_inner.GetGroup(id)))
                    throw new AdminAccessDeniedException("You can only add or remove the groups of your own role.");
            }
        }

        private static HashSet<int> GroupIds(User user)
        {
            var ids = new HashSet<int>(user?.SecondaryGroupIds ?? new List<int>());
            if (user?.PrimaryGroupId is { } primary)
                ids.Add(primary);
            return ids;
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
