using System;
using System.Collections.Generic;
using System.Linq;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FxSshSftpServer.Models
{
    /// <summary>The add/edit form of a group (issue #61). Every setting is optional: off means "not set by the group".</summary>
    public sealed class GroupForm
    {
        public int Id { get; init; }
        public string OriginalName { get; init; } = "";
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";

        /// <summary>The storage template of the members. No provider: not set.</summary>
        public StorageSettings Storage { get; init; } = new();

        public List<MountRow> Mounts { get; set; } = new();

        /// <summary>The group sets the permissions and path filters of its members.</summary>
        public bool SetPermissions { get; set; }

        public List<PermissionRow> Permissions { get; set; } = new() { PermissionRow.Root() };
        public List<PathFilterRow> PathFilters { get; set; } = new();

        /// <summary>The group sets the login methods of its members.</summary>
        public bool RestrictMethods { get; set; }
        public bool AllowPassword { get; set; } = true;
        public bool AllowPublicKey { get; set; } = true;

        /// <summary>The allowed methods that the form does not show (keyboard-interactive, #63); they are kept as stored.</summary>
        public AuthMethods OtherAllowedMethods { get; set; } = AuthMethods.KeyboardInteractive;

        /// <summary>The networks the members may log in from, one per line. Empty: not set.</summary>
        public string AllowedIps { get; set; } = "";

        /// <summary>The quotas and the bandwidth of the members without their own (issue #62); 0: not set.</summary>
        public QuotaForm Quotas { get; set; } = new();

        /// <summary>The scope role; kept as stored (the scoped repository sets it for a new group).</summary>
        public int? RoleId { get; init; }

        public IReadOnlyList<string> Members { get; init; } = [];

        public bool IsNew => Id == 0;

        public bool HasStorage => !string.IsNullOrEmpty(Storage.Provider);

        public static GroupForm New(StorageConfigService storage) => new() { Storage = storage.Edit(null) };

        public static GroupForm From(Group group, IReadOnlyList<string> members, StorageConfigService storage) => new()
        {
            Id = group.Id,
            OriginalName = group.Name,
            Name = group.Name,
            Description = group.Description ?? "",
            Storage = storage.Edit(group.Storage),
            Mounts = group.VirtualFolders
                .OrderBy(m => m.MountPath, StringComparer.Ordinal)
                .Select(MountRow.From)
                .ToList(),
            Quotas = QuotaForm.From(group.DiskQuota, group.TransferQuota, group.Bandwidth),
            SetPermissions = group.Permissions is { Count: > 0 } || (group.PathFilters ?? new()).Values.Any(f => !f.IsEmpty),
            Permissions = PermissionTables.RowsOf(group.Permissions),
            PathFilters = PermissionTables.FilterRowsOf(group.PathFilters),
            RestrictMethods = group.AllowedAuthMethods is not null,
            AllowPassword = group.AllowedAuthMethods?.HasFlag(AuthMethods.Password) ?? true,
            AllowPublicKey = group.AllowedAuthMethods?.HasFlag(AuthMethods.PublicKey) ?? true,
            OtherAllowedMethods = group.AllowedAuthMethods is { } methods ? methods & ~(AuthMethods.Password | AuthMethods.PublicKey) : AuthMethods.KeyboardInteractive,
            AllowedIps = EntryList.Format(group.AllowedIps),
            RoleId = group.RoleId,
            Members = members,
        };

        private AuthMethods AllowedMethods =>
            (AllowPassword ? AuthMethods.Password : AuthMethods.None) | (AllowPublicKey ? AuthMethods.PublicKey : AuthMethods.None) | OtherAllowedMethods;

        public List<VirtualFolderMount> MountList() => Mounts.Select(m => m.ToMount()).ToList();

        /// <summary>The group of the form, with the built storage template (null: not set).</summary>
        public Group ToGroup(StorageConfig storage)
        {
            var ips = EntryList.Parse(AllowedIps);
            return new Group
            {
                Id = Id,
                Name = Name.Trim(),
                Description = string.IsNullOrWhiteSpace(Description) ? null : Description.Trim(),
                Storage = storage,
                VirtualFolders = MountList(),
                Permissions = SetPermissions ? PermissionTables.ToDictionary(Permissions) : null,
                PathFilters = SetPermissions ? PermissionTables.NonEmptyFilters(PathFilters) : null,
                AllowedAuthMethods = RestrictMethods ? AllowedMethods : null,
                AllowedIps = ips.Count == 0 ? null : ips,
                DiskQuota = Quotas.Disk,
                TransferQuota = Quotas.Transfer,
                Bandwidth = Quotas.Bandwidth,
                RoleId = RoleId,
            };
        }

        /// <summary>The problems of the permission tables (shown under the tables); empty when the group sets no permissions.</summary>
        public (IReadOnlyList<string> Permissions, IReadOnlyList<string> Filters) TableProblems() =>
            SetPermissions ? PermissionTables.Problems(Permissions, PathFilters) : ([], []);

        /// <summary>The other problems: name, login methods, networks.</summary>
        public IReadOnlyList<string> Problems()
        {
            var problems = new List<string>();
            if (GroupService.ValidateName(Name) is { } name)
                problems.Add(name);
            if (RestrictMethods && !AllowPassword && !AllowPublicKey)
                problems.Add("Allow the password, the public key or both.");
            var invalid = SshServer.Interfaces.Net.CidrNotation.FindInvalid(EntryList.Parse(AllowedIps));
            if (invalid.Count > 0)
                problems.Add($"Not a valid network: {string.Join(", ", invalid)}.");
            problems.AddRange(Quotas.Problems(Mounts));
            return problems;
        }
    }
}
