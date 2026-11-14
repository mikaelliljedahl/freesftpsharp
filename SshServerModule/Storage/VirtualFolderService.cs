#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Storage
{
    /// <summary>
    /// The application service for virtual folders (issue #56), used by the admin UI and later the REST API (#67): the
    /// folders, their users, and the rules for names and mount paths.
    /// </summary>
    public sealed class VirtualFolderService
    {
        public const int MaximumNameLength = 100;
        public const int MaximumMountPathLength = 1024;

        private readonly ISettingsRepository _repository;

        public VirtualFolderService(ISettingsRepository repository)
        {
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        }

        public IReadOnlyList<VirtualFolder> List() => _repository.GetVirtualFolders();

        public VirtualFolder? Get(int id) => _repository.GetVirtualFolder(id);

        /// <summary>The names of the users that mount the folder.</summary>
        public IReadOnlyList<string> UsersOf(int id) => _repository.GetAllUsers()
            .Where(u => (u.VirtualFolders ?? []).Any(m => m.VirtualFolderId == id))
            .Select(u => u.Username)
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .ToList();

        /// <summary>Adds a folder. False when the name is already used (without case).</summary>
        public bool TryAdd(VirtualFolder folder)
        {
            folder.Name = folder.Name.Trim();
            if (_repository.GetVirtualFolders().Any(f => string.Equals(f.Name, folder.Name, StringComparison.OrdinalIgnoreCase)))
                return false;
            return _repository.AddVirtualFolder(folder);
        }

        /// <summary>Saves a folder. False when it does not exist or another folder has the name.</summary>
        public bool TryUpdate(VirtualFolder folder)
        {
            folder.Name = folder.Name.Trim();
            if (_repository.GetVirtualFolders().Any(f => f.Id != folder.Id && string.Equals(f.Name, folder.Name, StringComparison.OrdinalIgnoreCase)))
                return false;
            return _repository.UpdateVirtualFolder(folder);
        }

        /// <summary>Removes a folder and unmounts it from every user. The data in its storage stays.</summary>
        public bool Remove(int id) => _repository.RemoveVirtualFolder(id);

        /// <summary>An error text for the name, or null when it is valid.</summary>
        public static string? ValidateName(string? name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return "Enter a name.";
            if (name.Trim().Length > MaximumNameLength)
                return $"The name can have at most {MaximumNameLength} characters.";
            return null;
        }

        /// <summary>
        /// The problems of the mounts of a user: every mount path is absolute, not "/", not used twice (also not in
        /// another case), and every folder exists. The paths are compared after <see cref="VirtualPath.Normalize"/>.
        /// </summary>
        public IReadOnlyList<string> ValidateMounts(IEnumerable<VirtualFolderMount> mounts)
        {
            var problems = new List<string>();
            var folders = _repository.GetVirtualFolders().Select(f => f.Id).ToHashSet();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var mount in mounts)
            {
                var path = (mount.MountPath ?? string.Empty).Trim();
                if (!path.StartsWith('/'))
                {
                    problems.Add($"The mount path '{path}' must start with /.");
                    continue;
                }
                var normalized = VirtualPath.Normalize(path);
                if (normalized == VirtualPath.Root)
                    problems.Add("A virtual folder cannot be mounted at /; change the storage of the user instead.");
                else if (normalized.Length > MaximumMountPathLength)
                    problems.Add($"The mount path {normalized} is too long.");
                else if (!seen.Add(normalized))
                    problems.Add($"Two virtual folders are mounted at {normalized}.");
                if (!folders.Contains(mount.VirtualFolderId))
                    problems.Add($"Select a virtual folder for {normalized}.");
            }
            return problems;
        }
    }
}
