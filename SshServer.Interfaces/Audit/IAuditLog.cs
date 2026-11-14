namespace SshServer.Interfaces.Audit;

/// <summary>A filter of the audit log. A null value does not filter.</summary>
public sealed record AuditQuery
{
    /// <summary>The most entries one query returns (<see cref="Take"/> is limited to it); the CSV export asks for this many.</summary>
    public const int MaxTake = 100_000;

    /// <summary>The user name, exact (without case).</summary>
    public string? Username { get; init; }

    /// <summary>The <see cref="AuditEntry.Type"/>, for example "Upload".</summary>
    public string? Type { get; init; }

    /// <summary>The <see cref="AuditEntry.Status"/>.</summary>
    public string? Status { get; init; }

    /// <summary>Entries at or after this time, UTC.</summary>
    public DateTime? FromUtc { get; init; }

    /// <summary>Entries before this time, UTC.</summary>
    public DateTime? ToUtc { get; init; }

    public int Skip { get; init; }

    public int Take { get; init; } = 50;
}

/// <summary>One page of the audit log: the entries (newest first) and the number of all matching entries.</summary>
public sealed record AuditQueryResult(IReadOnlyList<AuditEntry> Entries, int TotalCount);

/// <summary>
/// The store of the audit log. The admin UI and later the REST API (#67) read it through this interface; the audit
/// sink writes to it.
/// </summary>
public interface IAuditLog
{
    /// <summary>False when the settings store has no audit table (the obsolete LiteDB provider).</summary>
    bool IsEnabled { get; }

    Task AppendAsync(AuditEntry entry, CancellationToken ct);

    /// <summary>The matching entries, newest first.</summary>
    Task<AuditQueryResult> QueryAsync(AuditQuery query, CancellationToken ct);

    /// <summary>Removes the entries older than <paramref name="cutoffUtc"/>; returns how many.</summary>
    Task<int> DeleteOlderThanAsync(DateTime cutoffUtc, CancellationToken ct);
}
