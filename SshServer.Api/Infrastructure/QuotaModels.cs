using SshServer.Interfaces.Net;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;

namespace SshServer.Api;

/// <summary>
/// The quotas and the bandwidth (#62) of a user or a group in the API, with the rules of the quota fields of the Users
/// and Groups pages: no negative value (0 is unlimited), and every bandwidth override has valid client networks. A quota
/// that limits nothing is stored as not set.
/// </summary>
internal static class QuotaModels
{
    public static void Validate(ValidationErrors errors, DiskQuota? disk, TransferQuota? transfer, BandwidthLimit? bandwidth,
        IEnumerable<VirtualFolderMount>? mounts = null)
    {
        if (disk is { MaxSizeBytes: < 0 } or { MaxFiles: < 0 } || (mounts ?? []).Any(m => m.Quota is { MaxSizeBytes: < 0 } or { MaxFiles: < 0 }))
            errors.Add("diskQuota", "A disk quota cannot be negative (0 is unlimited).");
        if (transfer is { MaxUploadBytes: < 0 } or { MaxDownloadBytes: < 0 } or { MaxTotalBytes: < 0 })
            errors.Add("transferQuota", "A transfer quota cannot be negative (0 is unlimited).");
        if (bandwidth is null)
            return;
        if (bandwidth.UploadKiBPerSecond < 0 || bandwidth.DownloadKiBPerSecond < 0
            || (bandwidth.Overrides ?? []).Any(o => o.UploadKiBPerSecond < 0 || o.DownloadKiBPerSecond < 0))
            errors.Add("bandwidth", "A bandwidth cannot be negative (0 is unlimited).");
        foreach (var entry in bandwidth.Overrides ?? [])
        {
            var sources = (entry.Sources ?? []).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToList();
            if (sources.Count == 0)
                errors.Add("bandwidth", "Enter the client networks of each bandwidth override.");
            foreach (var invalid in CidrNotation.FindInvalid(sources))
                errors.Add("bandwidth", $"Not a valid network: {invalid}");
            entry.Sources = sources;
        }
    }

    /// <summary>The quotas as they are stored: one that limits nothing is not set.</summary>
    public static (DiskQuota? Disk, TransferQuota? Transfer, BandwidthLimit? Bandwidth) Normalize(DiskQuota? disk, TransferQuota? transfer,
        BandwidthLimit? bandwidth)
    {
        if (bandwidth is { Overrides.Count: 0 })
            bandwidth.Overrides = null;
        return (DiskQuota.OrNull(disk), TransferQuota.OrNull(transfer), BandwidthLimit.OrNull(bandwidth));
    }
}
