namespace SshServer.Interfaces.Events;

/// <summary>The change of a <see cref="ProviderEvent"/>.</summary>
public enum ProviderAction
{
    Add,
    Update,
    Delete,
}

/// <summary>The kind of stored object of a <see cref="ProviderEvent"/>. Some kinds come with later roadmap items.</summary>
public enum ProviderObjectType
{
    User,
    Group,
    VirtualFolder,
    Admin,
    Role,
    ApiKey,
    Share,
    EventRule,
    Webhook,

    /// <summary>The server settings (one object).</summary>
    ServerSettings,
}

/// <summary>A stored object was added, changed or removed.</summary>
/// <param name="Action">The change.</param>
/// <param name="ObjectType">The kind of object.</param>
/// <param name="ObjectName">The name of the object, for example the user name.</param>
public sealed record ProviderEvent(ProviderAction Action, ProviderObjectType ObjectType, string ObjectName) : IEvent
{
    public EventCategory Category => EventCategory.Provider;

    public string TypeName => Action.ToString();

    public DateTimeOffset Timestamp { get; init; }

    /// <summary>Who made the change: an admin name, an API key, "self", or null when the store does not know it.</summary>
    public string? Actor { get; init; }

    /// <summary>The object after the change (before a delete), without secrets, for example a <see cref="UserSnapshot"/>.</summary>
    public object? Object { get; init; }

    /// <summary>The names of the changed fields of an <see cref="ProviderAction.Update"/>.</summary>
    public IReadOnlyList<string> ChangedFields { get; init; } = [];
}

/// <summary>
/// A <see cref="User"/> without its password hash and public keys: only whether it has them, and the fingerprints of the
/// keys (not secret, they identify a key in the audit log).
/// </summary>
/// <param name="StorageProvider">The provider of <see cref="User.Storage"/>; null for the default storage. The options are left out (they can have secrets).</param>
/// <param name="VirtualFolders">The mounts, as "mount path=virtual folder id".</param>
/// <param name="SecondaryGroupIds">The secondary groups, as comma separated ids in their order.</param>
/// <param name="DiskQuota">The disk quotas (issue #62) as text: the own storage, then each mount with a quota.</param>
/// <param name="TransferQuota">The transfer quota as text.</param>
/// <param name="Bandwidth">The bandwidth as text.</param>
public sealed record UserSnapshot(string Username, string UserRootDirectory, bool HasPassword, bool HasPublicKey,
    bool OnlyWhitelistedIps, IReadOnlyList<string> WhitelistedIps, IReadOnlyList<string> PublicKeyFingerprints,
    string AllowedAuthMethods, string RequireAllOf, string? StorageProvider, IReadOnlyList<string> VirtualFolders,
    string Status, DateTime? ExpiresAt, int MaxSessions, string? Description, int? PrimaryGroupId, string SecondaryGroupIds,
    string DiskQuota, string TransferQuota, string Bandwidth)
{
    public static UserSnapshot From(User user) => new(user.Username, user.UserRootDirectory,
        !string.IsNullOrEmpty(user.HashedPassword), user.PublicKeys is { Count: > 0 },
        user.OnlyWhitelistedIps, user.WhitelistedIps?.ToList() ?? [],
        user.PublicKeys?.Select(k => k.Fingerprint).ToList() ?? [],
        user.AllowedAuthMethods.ToString(), string.Join(",", user.RequireAllOf ?? []), user.Storage?.Provider,
        (user.VirtualFolders ?? []).Select(m => $"{m.MountPath}={m.VirtualFolderId}").ToList(),
        user.Status.ToString(), user.ExpiresAt, user.MaxSessions, user.Description, user.PrimaryGroupId,
        string.Join(",", user.SecondaryGroupIds ?? []),
        QuotaText.Disk(user.DiskQuota, user.VirtualFolders), QuotaText.Transfer(user.TransferQuota), QuotaText.Bandwidth(user.Bandwidth));
}

/// <summary>A <see cref="Groups.Group"/> without its storage options (they can have secrets).</summary>
/// <param name="Permissions">The permissions, as "path=flags".</param>
/// <param name="PathFilters">The filters, as "path=allowed;denied;hidden" with comma separated patterns.</param>
/// <param name="VirtualFolders">The mounts, as "mount path=virtual folder id".</param>
public sealed record GroupSnapshot(int Id, string Name, string? Description, IReadOnlyList<string> Permissions,
    IReadOnlyList<string> PathFilters, string? StorageProvider, IReadOnlyList<string> VirtualFolders, string? AllowedAuthMethods,
    IReadOnlyList<string> AllowedIps, int? RoleId, string DiskQuota, string TransferQuota, string Bandwidth)
{
    public static GroupSnapshot From(Groups.Group group) => new(group.Id, group.Name, group.Description,
        (group.Permissions ?? []).OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => $"{p.Key}={p.Value}").ToList(),
        (group.PathFilters ?? []).OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => $"{p.Key}={string.Join(",", p.Value.AllowedPatterns)};{string.Join(",", p.Value.DeniedPatterns)};{string.Join(",", p.Value.HiddenPatterns)}").ToList(),
        group.Storage?.Provider,
        group.VirtualFolders.Select(m => $"{m.MountPath}={m.VirtualFolderId}").ToList(),
        group.AllowedAuthMethods?.ToString(), group.AllowedIps?.ToList() ?? [], group.RoleId,
        QuotaText.Disk(group.DiskQuota, group.VirtualFolders), QuotaText.Transfer(group.TransferQuota), QuotaText.Bandwidth(group.Bandwidth));
}

/// <summary>The quotas (issue #62) of a user or a group as text for the snapshots: "unlimited" or the values.</summary>
internal static class QuotaText
{
    public static string Disk(Quotas.DiskQuota? own, IEnumerable<Storage.VirtualFolderMount>? mounts)
    {
        var parts = new List<string> { "/: " + (Quotas.DiskQuota.OrNull(own)?.ToString() ?? "unlimited") };
        foreach (var mount in mounts ?? [])
        {
            if (Quotas.DiskQuota.OrNull(mount.Quota) is { } quota)
                parts.Add($"{mount.MountPath}: {quota}");
        }
        return string.Join("; ", parts);
    }

    public static string Transfer(Quotas.TransferQuota? quota) => Quotas.TransferQuota.OrNull(quota)?.ToString() ?? "unlimited";

    public static string Bandwidth(Quotas.BandwidthLimit? limit) => Quotas.BandwidthLimit.OrNull(limit)?.ToString() ?? "unlimited";
}

/// <summary>A <see cref="Storage.VirtualFolder"/> without its storage options (they can have secrets).</summary>
public sealed record VirtualFolderSnapshot(int Id, string Name, string? Description, string StorageProvider)
{
    public static VirtualFolderSnapshot From(Storage.VirtualFolder folder) => new(folder.Id, folder.Name, folder.Description, folder.Storage.Provider);
}

/// <summary>The <see cref="ServerSettings"/> without the host keys.</summary>
public sealed record ServerSettingsSnapshot(string? ServerBanner, int ListenToPort, IReadOnlyList<string> BindToAddress,
    IReadOnlyList<string> BlacklistedIps, bool OnlyWhitelistedIps, IReadOnlyList<string> WhitelistedIps,
    int MaxLoginAttemptsBeforeBan, int LoginFailureWindowSeconds, int BanDurationSeconds, bool ExemptLoopbackFromBan,
    int IdleTimeout, bool EnableCommand, bool EnableDirectTcpIp, int PasswordMaxAgeDays)
{
    public static ServerSettingsSnapshot From(ServerSettings s) => new(s.ServerBanner, s.ListenToPort,
        s.BindToAddress?.ToList() ?? [], s.BlacklistedIps?.ToList() ?? [], s.OnlyWhitelistedIps, s.WhitelistedIps?.ToList() ?? [],
        s.MaxLoginAttemptsBeforeBan, s.LoginFailureWindowSeconds, s.BanDurationSeconds, s.ExemptLoopbackFromBan,
        s.IdleTimeout, s.EnableCommand, s.EnableDirectTcpIp, s.PasswordMaxAgeDays);
}
