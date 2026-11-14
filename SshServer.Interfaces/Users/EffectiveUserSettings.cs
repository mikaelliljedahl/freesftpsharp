using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;

namespace SshServer.Interfaces.Users;

/// <summary>Where an effective setting of a user comes from.</summary>
public enum SettingSource
{
    /// <summary>The user sets it itself.</summary>
    User,

    /// <summary>The primary group of the user.</summary>
    PrimaryGroup,

    /// <summary>A secondary group of the user.</summary>
    SecondaryGroup,

    /// <summary>Nobody sets it: the server default.</summary>
    Default,
}

/// <summary>The source of an effective setting, with the group name for <see cref="SettingSource.PrimaryGroup"/> and <see cref="SettingSource.SecondaryGroup"/>.</summary>
public sealed record SettingOrigin(SettingSource Source, string? GroupName = null)
{
    public static SettingOrigin User { get; } = new(SettingSource.User);

    public static SettingOrigin Default { get; } = new(SettingSource.Default);

    public bool IsInherited => Source is SettingSource.PrimaryGroup or SettingSource.SecondaryGroup;

    /// <summary>For the admin UI: "user", "group sales" or "server default".</summary>
    public override string ToString() => Source switch
    {
        SettingSource.User => "user",
        SettingSource.Default => "server default",
        _ => $"group {GroupName}",
    };
}

/// <summary>A virtual folder mounted for a user, by the user itself or by one of its groups.</summary>
public sealed record EffectiveMount(int VirtualFolderId, string MountPath, SettingOrigin Origin);

/// <summary>
/// The settings that apply to one user (issue #61), from <see cref="IEffectiveUserSettingsService"/>: its own values
/// over the values of its groups over the server defaults. The protocols, the storage and the admin UI read the
/// settings of a user only from here, so they always agree.
/// </summary>
public sealed class EffectiveUserSettings
{
    /// <summary>The stored user.</summary>
    public required User User { get; init; }

    /// <summary>The groups of the user that exist, primary first, then the secondary groups in their order.</summary>
    public required IReadOnlyList<Group> Groups { get; init; }

    /// <summary>The permissions and path filters (each of the two comes from one source as a whole).</summary>
    public required EffectivePermissions Permissions { get; init; }

    public required SettingOrigin PermissionsOrigin { get; init; }

    public required SettingOrigin PathFiltersOrigin { get; init; }

    /// <summary>
    /// The storage of "/" with the user name in place of <see cref="StorageTemplate.UsernamePlaceholder"/>; null: the
    /// default storage of the server (the local disk at <see cref="User.UserRootDirectory"/>).
    /// </summary>
    public StorageConfig? Storage { get; init; }

    public required SettingOrigin StorageOrigin { get; init; }

    /// <summary>Why the storage template of a group cannot be used for this user, or null. The storage is then refused.</summary>
    public string? StorageProblem { get; init; }

    /// <summary>The mounted virtual folders: the user's own, then those of the groups at a path that is still free.</summary>
    public required IReadOnlyList<EffectiveMount> VirtualFolders { get; init; }

    public required AuthMethods AllowedAuthMethods { get; init; }

    public required SettingOrigin AllowedAuthMethodsOrigin { get; init; }

    /// <summary>The networks the user may log in from. Empty: any network.</summary>
    public required IReadOnlyList<string> AllowedIps { get; init; }

    public required SettingOrigin AllowedIpsOrigin { get; init; }
}

/// <summary>
/// The one place that resolves the settings of a user (issues #59 and #61). Everything that reads a setting which a
/// group can set (permissions, path filters, storage, virtual folders, login methods, allowed networks) uses it, never
/// the fields of <see cref="User"/> or <see cref="Group"/> itself.
/// </summary>
public interface IEffectiveUserSettingsService
{
    EffectiveUserSettings Resolve(User user);
}
