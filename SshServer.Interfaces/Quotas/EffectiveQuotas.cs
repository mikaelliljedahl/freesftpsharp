using SshServer.Interfaces.Storage;

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

    /// <summary>The disk quota of the mount at <paramref name="mountPath"/>, or null.</summary>
    public DiskQuota? ForMount(string mountPath) => Mounts.TryGetValue(VirtualPath.Normalize(mountPath), out var quota) ? quota : null;
}

/// <summary>
/// The one place that decides which quotas and which bandwidth apply to a user. The storage factory gets them here,
/// never from the user itself. When groups (#61) come, their defaults are merged here.
/// </summary>
public interface IEffectiveQuotaService
{
    EffectiveQuotas Resolve(User user);
}

/// <summary>The quotas of a user are its own <see cref="User.DiskQuota"/>, <see cref="User.TransferQuota"/>, <see cref="User.Bandwidth"/> and the quota of each mount.</summary>
public sealed class EffectiveQuotaService : IEffectiveQuotaService
{
    public EffectiveQuotas Resolve(User user)
    {
        var mounts = new Dictionary<string, DiskQuota>(StringComparer.Ordinal);
        foreach (var mount in user.VirtualFolders ?? [])
        {
            if (DiskQuota.OrNull(mount.Quota) is { } quota)
                mounts[VirtualPath.Normalize(mount.MountPath)] = quota;
        }
        var result = new EffectiveQuotas(DiskQuota.OrNull(user.DiskQuota), mounts, TransferQuota.OrNull(user.TransferQuota), BandwidthLimit.OrNull(user.Bandwidth));
        return result.IsUnlimited ? EffectiveQuotas.Unlimited : result;
    }
}
