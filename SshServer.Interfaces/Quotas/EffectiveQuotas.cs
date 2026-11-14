using SshServer.Interfaces.Storage;
using SshServer.Interfaces.Users;

namespace SshServer.Interfaces.Quotas;

/// <summary>
/// The quotas and the bandwidth that apply to a user (issue #62). Null means unlimited, so a user without any limit
/// (<see cref="IsUnlimited"/>) gets no quota decorator at all.
/// </summary>
/// <param name="Disk">The disk quota of the own storage of the user ("/" without the virtual folders).</param>
/// <param name="Mounts">The disk quota of each virtual folder mount that has one, by its normalized mount path.</param>
/// <param name="Transfer">The transfer quota of the user.</param>
/// <param name="Bandwidth">The bandwidth of the sessions of the user.</param>
public sealed record EffectiveQuotas(DiskQuota? Disk, IReadOnlyDictionary<string, DiskQuota> Mounts, TransferQuota? Transfer, BandwidthLimit? Bandwidth)
{
    public static EffectiveQuotas Unlimited { get; } = new(null, new Dictionary<string, DiskQuota>(), null, null);

    public bool IsUnlimited => Disk is null && Mounts.Count == 0 && Transfer is null && Bandwidth is null;

    /// <summary>True when the own storage or a virtual folder has a disk quota.</summary>
    public bool HasDiskQuota => Disk is not null || Mounts.Count > 0;

    /// <summary>The quotas of the effective settings of a user (its own values, else those of its groups).</summary>
    public static EffectiveQuotas From(EffectiveUserSettings settings)
    {
        var mounts = new Dictionary<string, DiskQuota>(StringComparer.Ordinal);
        foreach (var mount in settings.VirtualFolders)
        {
            if (DiskQuota.OrNull(mount.Quota) is { } quota)
                mounts[VirtualPath.Normalize(mount.MountPath)] = quota;
        }
        var result = new EffectiveQuotas(settings.DiskQuota, mounts, settings.TransferQuota, settings.Bandwidth);
        return result.IsUnlimited ? Unlimited : result;
    }

    /// <summary>The disk quota of the mount at <paramref name="mountPath"/>, or null.</summary>
    public DiskQuota? ForMount(string mountPath) => Mounts.TryGetValue(VirtualPath.Normalize(mountPath), out var quota) ? quota : null;
}

/// <summary>
/// The quotas and the bandwidth that apply to a user. They are settings of <see cref="IEffectiveUserSettingsService"/>
/// (the user, then its groups, #61), so this service only takes them from there.
/// </summary>
public interface IEffectiveQuotaService
{
    EffectiveQuotas Resolve(User user);
}

/// <summary>The quotas of the effective settings of a user (<see cref="EffectiveQuotas.From"/>).</summary>
public sealed class EffectiveQuotaService : IEffectiveQuotaService
{
    private readonly IEffectiveUserSettingsService _settings;

    public EffectiveQuotaService(IEffectiveUserSettingsService settings)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
    }

    public EffectiveQuotas Resolve(User user) => EffectiveQuotas.From(_settings.Resolve(user));
}
