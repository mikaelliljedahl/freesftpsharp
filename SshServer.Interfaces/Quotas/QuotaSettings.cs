using System.Globalization;
using System.Net;
using System.Text.Json.Serialization;
using SshServer.Interfaces.Net;

namespace SshServer.Interfaces.Quotas;

/// <summary>
/// A disk quota (issue #62): how much one storage (the user's own storage, or a virtual folder mounted for the user) may
/// hold. 0 is unlimited. The usage is counted by the storage decorator (approximately, as in SFTPGo) and corrected by a
/// scan.
/// </summary>
public sealed class DiskQuota
{
    /// <summary>The maximum total size of the files in bytes; 0: unlimited.</summary>
    public long MaxSizeBytes { get; set; }

    /// <summary>The maximum number of files; 0: unlimited.</summary>
    public long MaxFiles { get; set; }

    /// <summary>True when neither the size nor the number of files is limited.</summary>
    [JsonIgnore]
    public bool IsUnlimited => MaxSizeBytes <= 0 && MaxFiles <= 0;

    /// <summary>The quota, or null when it limits nothing (null and unlimited mean the same).</summary>
    public static DiskQuota? OrNull(DiskQuota? quota) => quota is { IsUnlimited: false } ? quota : null;

    public override string ToString() => IsUnlimited
        ? "unlimited"
        : string.Create(CultureInfo.InvariantCulture, $"{(MaxSizeBytes > 0 ? $"{MaxSizeBytes} bytes" : "any size")}, {(MaxFiles > 0 ? $"{MaxFiles} files" : "any number of files")}");
}

/// <summary>
/// A transfer quota (issue #62): how much a user may upload and download until an administrator resets the counters.
/// 0 is unlimited. It counts every protocol and every storage of the user.
/// </summary>
public sealed class TransferQuota
{
    /// <summary>The maximum of uploaded bytes; 0: unlimited.</summary>
    public long MaxUploadBytes { get; set; }

    /// <summary>The maximum of downloaded bytes; 0: unlimited.</summary>
    public long MaxDownloadBytes { get; set; }

    /// <summary>The maximum of uploaded and downloaded bytes together; 0: unlimited.</summary>
    public long MaxTotalBytes { get; set; }

    [JsonIgnore]
    public bool IsUnlimited => MaxUploadBytes <= 0 && MaxDownloadBytes <= 0 && MaxTotalBytes <= 0;

    /// <summary>The quota, or null when it limits nothing.</summary>
    public static TransferQuota? OrNull(TransferQuota? quota) => quota is { IsUnlimited: false } ? quota : null;

    public override string ToString() => IsUnlimited
        ? "unlimited"
        : string.Create(CultureInfo.InvariantCulture, $"upload {Format(MaxUploadBytes)}, download {Format(MaxDownloadBytes)}, total {Format(MaxTotalBytes)}");

    private static string Format(long value) => value > 0 ? value.ToString(CultureInfo.InvariantCulture) : "unlimited";
}

/// <summary>
/// The bandwidth of a user (issue #62), per session and direction, in KiB per second; 0 is unlimited. An override for
/// client networks (for example the LAN) replaces both values for a client in one of its networks; the first matching
/// override wins.
/// </summary>
public sealed class BandwidthLimit
{
    public int UploadKiBPerSecond { get; set; }

    public int DownloadKiBPerSecond { get; set; }

    /// <summary>Other values for clients in some networks. Null or empty: none.</summary>
    public List<BandwidthOverride>? Overrides { get; set; }

    /// <summary>True when no client is limited (no value and no override limits anything).</summary>
    [JsonIgnore]
    public bool IsUnlimited => UploadKiBPerSecond <= 0 && DownloadKiBPerSecond <= 0
                               && (Overrides ?? []).All(o => o.UploadKiBPerSecond <= 0 && o.DownloadKiBPerSecond <= 0);

    /// <summary>The limit, or null when it limits nothing.</summary>
    public static BandwidthLimit? OrNull(BandwidthLimit? limit) => limit is { IsUnlimited: false } ? limit : null;

    /// <summary>
    /// The upload and download rate in bytes per second for a client (0: unlimited): the first override with a network
    /// that holds <paramref name="remoteIp"/>, else the values of the user. A client without a known address gets the values of the user.
    /// </summary>
    public (long UploadBytesPerSecond, long DownloadBytesPerSecond) For(string? remoteIp)
    {
        var (upload, download) = (UploadKiBPerSecond, DownloadKiBPerSecond);
        if (remoteIp is not null && IPAddress.TryParse(remoteIp, out var address))
        {
            foreach (var entry in Overrides ?? [])
            {
                if (CidrNotation.Contains(CidrNotation.ParseValid(entry.Sources), address))
                {
                    (upload, download) = (entry.UploadKiBPerSecond, entry.DownloadKiBPerSecond);
                    break;
                }
            }
        }
        return (Math.Max(0, upload) * 1024L, Math.Max(0, download) * 1024L);
    }

    public override string ToString()
    {
        var text = string.Create(CultureInfo.InvariantCulture, $"upload {Format(UploadKiBPerSecond)}, download {Format(DownloadKiBPerSecond)}");
        foreach (var entry in Overrides ?? [])
            text += string.Create(CultureInfo.InvariantCulture, $"; {string.Join(",", entry.Sources ?? [])}: upload {Format(entry.UploadKiBPerSecond)}, download {Format(entry.DownloadKiBPerSecond)}");
        return text;
    }

    private static string Format(int value) => value > 0 ? value.ToString(CultureInfo.InvariantCulture) + " KiB/s" : "unlimited";
}

/// <summary>The bandwidth for clients in some networks (<see cref="BandwidthLimit.Overrides"/>); 0 is unlimited.</summary>
public sealed class BandwidthOverride
{
    /// <summary>The client networks in CIDR notation, for example "10.0.0.0/8".</summary>
    public List<string> Sources { get; set; } = [];

    public int UploadKiBPerSecond { get; set; }

    public int DownloadKiBPerSecond { get; set; }
}
