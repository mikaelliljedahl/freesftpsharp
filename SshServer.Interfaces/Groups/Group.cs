using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;

namespace SshServer.Interfaces.Groups;

/// <summary>
/// A group of SFTP users (issue #61): a template of shared settings. A user is in at most one primary group
/// (<see cref="User.PrimaryGroupId"/>) and in any number of secondary groups (<see cref="User.SecondaryGroupIds"/>).
/// A setting that the user does not set itself comes from its groups (<see cref="Users.IEffectiveUserSettingsService"/>);
/// every setting here is optional, null (or empty) means "not set by this group".
/// <para>
/// Add a new shared setting as one more nullable property, and resolve it in
/// <see cref="Users.EffectiveUserSettingsService"/>; nothing else reads the groups.
/// </para>
/// </summary>
public sealed class Group
{
    public int Id { get; set; }

    /// <summary>The unique name (compared without case).</summary>
    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    /// <summary>The permissions per virtual directory, like <see cref="User.Permissions"/>. Null or empty: not set.</summary>
    public Dictionary<string, FilePermissions>? Permissions { get; set; }

    /// <summary>The file name filters per virtual directory, like <see cref="User.PathFilters"/>. Null or empty: not set.</summary>
    public Dictionary<string, PathFilter>? PathFilters { get; set; }

    /// <summary>
    /// The storage of "/" of the members without a storage of their own: a template, in which
    /// <see cref="StorageTemplate.UsernamePlaceholder"/> in a text option (a local directory, a key prefix) is replaced
    /// by the user name, so every member gets its own folder. Null: not set.
    /// </summary>
    public StorageConfig? Storage { get; set; }

    /// <summary>The virtual folders that are mounted for every member (in addition to the user's own mounts).</summary>
    public List<VirtualFolderMount> VirtualFolders { get; set; } = new();

    /// <summary>The login methods of the members whose own setting allows every method. Null: not set.</summary>
    public AuthMethods? AllowedAuthMethods { get; set; }

    /// <summary>The networks (CIDR or single addresses) the members may log in from, like the IP whitelist of a user. Null or empty: not set.</summary>
    public List<string>? AllowedIps { get; set; }

    /// <summary>The disk quota of the own storage of the members without one of their own (issue #62). Null: not set.</summary>
    public DiskQuota? DiskQuota { get; set; }

    /// <summary>The transfer quota of the members without one of their own (issue #62). Null: not set.</summary>
    public TransferQuota? TransferQuota { get; set; }

    /// <summary>The bandwidth of the members without one of their own (issue #62). Null: not set.</summary>
    public BandwidthLimit? Bandwidth { get; set; }

    /// <summary>
    /// The scope role (issue #60): an administrator with this role as its scope manages the group and can give it to its
    /// users. Null: only administrators without a scope see the group.
    /// </summary>
    public int? RoleId { get; set; }

    public Group Clone() => new()
    {
        Id = Id,
        Name = Name,
        Description = Description,
        Permissions = Permissions?.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal),
        PathFilters = PathFilters?.ToDictionary(p => p.Key, p => new PathFilter
        {
            AllowedPatterns = p.Value.AllowedPatterns.ToList(),
            DeniedPatterns = p.Value.DeniedPatterns.ToList(),
            HiddenPatterns = p.Value.HiddenPatterns.ToList(),
        }, StringComparer.Ordinal),
        Storage = Storage,
        VirtualFolders = VirtualFolders.Select(m => new VirtualFolderMount { VirtualFolderId = m.VirtualFolderId, MountPath = m.MountPath, Quota = m.Quota }).ToList(),
        AllowedAuthMethods = AllowedAuthMethods,
        AllowedIps = AllowedIps?.ToList(),
        DiskQuota = DiskQuota,
        TransferQuota = TransferQuota,
        Bandwidth = Bandwidth,
        RoleId = RoleId,
    };
}
