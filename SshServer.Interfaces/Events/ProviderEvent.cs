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
/// <param name="DiskQuota">The disk quotas (issue #62) as text: the own storage, then each mount with a quota.</param>
/// <param name="TransferQuota">The transfer quota as text.</param>
/// <param name="Bandwidth">The bandwidth as text.</param>
public sealed record UserSnapshot(string Username, string UserRootDirectory, bool HasPassword, bool HasPublicKey,
    bool OnlyWhitelistedIps, IReadOnlyList<string> WhitelistedIps, IReadOnlyList<string> PublicKeyFingerprints,
    string AllowedAuthMethods, string RequireAllOf, string? StorageProvider, IReadOnlyList<string> VirtualFolders,
    string DiskQuota, string TransferQuota, string Bandwidth)
{
    public static UserSnapshot From(User user) => new(user.Username, user.UserRootDirectory,
        !string.IsNullOrEmpty(user.HashedPassword), user.PublicKeys is { Count: > 0 },
        user.OnlyWhitelistedIps, user.WhitelistedIps?.ToList() ?? [],
        user.PublicKeys?.Select(k => k.Fingerprint).ToList() ?? [],
        user.AllowedAuthMethods.ToString(), string.Join(",", user.RequireAllOf ?? []), user.Storage?.Provider,
        (user.VirtualFolders ?? []).Select(m => $"{m.MountPath}={m.VirtualFolderId}").ToList(),
        DiskQuotaText(user), Quotas.TransferQuota.OrNull(user.TransferQuota)?.ToString() ?? "unlimited",
        Quotas.BandwidthLimit.OrNull(user.Bandwidth)?.ToString() ?? "unlimited");

    private static string DiskQuotaText(User user)
    {
        var parts = new List<string> { "/: " + (Quotas.DiskQuota.OrNull(user.DiskQuota)?.ToString() ?? "unlimited") };
        foreach (var mount in user.VirtualFolders ?? [])
        {
            if (Quotas.DiskQuota.OrNull(mount.Quota) is { } quota)
                parts.Add($"{mount.MountPath}: {quota}");
        }
        return string.Join("; ", parts);
    }
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
    int IdleTimeout, bool EnableCommand, bool EnableDirectTcpIp)
{
    public static ServerSettingsSnapshot From(ServerSettings s) => new(s.ServerBanner, s.ListenToPort,
        s.BindToAddress?.ToList() ?? [], s.BlacklistedIps?.ToList() ?? [], s.OnlyWhitelistedIps, s.WhitelistedIps?.ToList() ?? [],
        s.MaxLoginAttemptsBeforeBan, s.LoginFailureWindowSeconds, s.BanDurationSeconds, s.ExemptLoopbackFromBan,
        s.IdleTimeout, s.EnableCommand, s.EnableDirectTcpIp);
}
