#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.Users;

namespace SshServerModule.Storage
{
    /// <summary>
    /// The storage of a user (issue #56): the effective storage (<see cref="IEffectiveUserSettingsService"/>: the user's
    /// own, or the template of a group, issue #61), or the <see cref="IDefaultUserStorage"/> (the local disk at the user
    /// root) for a user without one, and the effective virtual folders (the user's and its groups') from the settings
    /// repository.
    /// </summary>
    public sealed class UserStorageResolver : IUserStorageResolver
    {
        private readonly IDefaultUserStorage? _defaults;
        private readonly ISettingsRepository? _repository;
        private readonly IEffectiveUserSettingsService _settings;

        /// <param name="defaults">The storage of a user without a configuration (AddLocalDiskStorage). Null: such a user has no storage.</param>
        /// <param name="repository">The settings, for the virtual folders. Null: a user with a virtual folder has no storage.</param>
        /// <param name="settings">The effective settings of the users (AddSshServerStorage). Null: one over <paramref name="repository"/>.</param>
        public UserStorageResolver(IDefaultUserStorage? defaults = null, ISettingsRepository? repository = null, IEffectiveUserSettingsService? settings = null)
        {
            _defaults = defaults;
            _repository = repository;
            _settings = settings ?? new EffectiveUserSettingsService(repository);
        }

        public UserStorage Resolve(User user)
        {
            var effective = _settings.Resolve(user);
            if (effective.StorageProblem != null)
                throw new ArgumentException(effective.StorageProblem);
            var root = effective.Storage
                       ?? _defaults?.For(user)
                       ?? throw new ArgumentException($"The user {user.Username} has no storage configuration, and no default storage is registered.");

            var mounts = new List<StorageMount>();
            foreach (var mount in effective.VirtualFolders)
            {
                var folder = _repository?.GetVirtualFolder(mount.VirtualFolderId)
                             ?? throw new ArgumentException($"The virtual folder {mount.VirtualFolderId} mounted at {mount.MountPath} does not exist.");
                mounts.Add(new StorageMount(VirtualPath.Normalize(mount.MountPath), folder.Name, folder.Storage, folder.Id));
            }
            return new UserStorage(root, mounts);
        }
    }
}
