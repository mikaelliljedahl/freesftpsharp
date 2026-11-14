namespace SshServer.Interfaces.Quotas;

/// <summary>What a quota counts for: the own storage of a user, or a virtual folder (shared by every user that mounts it).</summary>
public enum QuotaScopeKind
{
    User,
    VirtualFolder,
}

/// <summary>
/// One counter of the quota usage (issue #62): a user (by its stored user name, which cannot change) or a virtual folder (by
/// its id). <see cref="ToString"/> is the stored key, for example "user:alice" or "folder:3".
/// </summary>
public readonly record struct QuotaScope(QuotaScopeKind Kind, string Key)
{
    /// <summary>The own storage of the user (its "/" without the virtual folders), and its transfers.</summary>
    public static QuotaScope ForUser(string username) => new(QuotaScopeKind.User, username);

    /// <summary>A virtual folder, for every user that mounts it.</summary>
    public static QuotaScope ForFolder(int folderId) => new(QuotaScopeKind.VirtualFolder, folderId.ToString(System.Globalization.CultureInfo.InvariantCulture));

    public override string ToString() => (Kind == QuotaScopeKind.User ? "user:" : "folder:") + Key;
}

/// <summary>The counters of a <see cref="QuotaScope"/>.</summary>
/// <param name="UsedBytes">The size of the files in the storage.</param>
/// <param name="UsedFiles">The number of files in the storage.</param>
/// <param name="UploadedBytes">The bytes uploaded since the last reset of the transfer counters (user scope only).</param>
/// <param name="DownloadedBytes">The bytes downloaded since the last reset of the transfer counters (user scope only).</param>
/// <param name="ScannedAt">The time of the last scan of the storage; null: never scanned, the disk counters are only what the server saw.</param>
/// <param name="UpdatedAt">The time of the last change.</param>
public sealed record QuotaUsage(long UsedBytes, long UsedFiles, long UploadedBytes, long DownloadedBytes, DateTimeOffset? ScannedAt, DateTimeOffset UpdatedAt)
{
    public static QuotaUsage Empty { get; } = new(0, 0, 0, 0, null, DateTimeOffset.MinValue);

    /// <summary>These counters with <paramref name="delta"/> added.</summary>
    public QuotaUsage Add(QuotaUsageDelta delta) => this with
    {
        UsedBytes = UsedBytes + delta.Bytes,
        UsedFiles = UsedFiles + delta.Files,
        UploadedBytes = UploadedBytes + delta.Uploaded,
        DownloadedBytes = DownloadedBytes + delta.Downloaded,
    };
}

/// <summary>A change of the counters of a <see cref="QuotaScope"/>; each value can be negative.</summary>
public readonly record struct QuotaUsageDelta(long Bytes, long Files, long Uploaded, long Downloaded)
{
    public bool IsZero => Bytes == 0 && Files == 0 && Uploaded == 0 && Downloaded == 0;

    public static QuotaUsageDelta operator +(QuotaUsageDelta a, QuotaUsageDelta b)
        => new(a.Bytes + b.Bytes, a.Files + b.Files, a.Uploaded + b.Uploaded, a.Downloaded + b.Downloaded);
}

/// <summary>
/// The stored quota counters (issue #62), shared by the nodes of the server: the settings database
/// (<c>QuotaUsages</c>), or memory with the LiteDB settings. Changes are increments, so several nodes can add to the same
/// counter. Each method returns the stored counters after the change.
/// </summary>
public interface IQuotaUsageStore
{
    /// <summary>The counters, or null when the scope has none yet.</summary>
    Task<QuotaUsage?> GetAsync(QuotaScope scope, CancellationToken ct);

    /// <summary>Adds <paramref name="delta"/> to the counters (a scope without counters starts at 0).</summary>
    Task<QuotaUsage> AddAsync(QuotaScope scope, QuotaUsageDelta delta, DateTimeOffset now, CancellationToken ct);

    /// <summary>Sets the disk counters to the result of a scan; the transfer counters stay.</summary>
    Task<QuotaUsage> SetDiskUsageAsync(QuotaScope scope, long usedBytes, long usedFiles, DateTimeOffset scannedAt, CancellationToken ct);

    /// <summary>Sets the transfer counters to 0; the disk counters stay.</summary>
    Task<QuotaUsage> ResetTransferAsync(QuotaScope scope, DateTimeOffset now, CancellationToken ct);

    /// <summary>Removes the counters (the user or the folder was removed).</summary>
    Task RemoveAsync(QuotaScope scope, CancellationToken ct);
}
