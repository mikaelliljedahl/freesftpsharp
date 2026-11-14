using Microsoft.EntityFrameworkCore;
using SshServer.Interfaces.Quotas;

namespace SshServer.Settings.Sql.Quotas;

/// <summary>A row of the table QuotaUsages: the counters of one <see cref="QuotaScope"/> (its <see cref="QuotaScope.ToString"/>).</summary>
public sealed class QuotaUsageRow
{
    public string Scope { get; set; } = string.Empty;
    public long UsedBytes { get; set; }
    public long UsedFiles { get; set; }
    public long UploadedBytes { get; set; }
    public long DownloadedBytes { get; set; }

    /// <summary>The last scan of the storage (UTC); null: never scanned.</summary>
    public DateTime? ScannedUtc { get; set; }

    public DateTime UpdatedUtc { get; set; }

    public QuotaUsage ToUsage() => new(UsedBytes, UsedFiles, UploadedBytes, DownloadedBytes,
        ScannedUtc is { } scanned ? new DateTimeOffset(DateTime.SpecifyKind(scanned, DateTimeKind.Utc)) : null,
        new DateTimeOffset(DateTime.SpecifyKind(UpdatedUtc, DateTimeKind.Utc)));
}

/// <summary>
/// <see cref="IQuotaUsageStore"/> in the table QuotaUsages of the settings database (issue #62). An increment is one
/// UPDATE that adds to the stored values, so several nodes can change the same counter; a missing row is inserted. The
/// settings repository creates and migrates the database at the start; each call has its own context.
/// </summary>
public sealed class SqlQuotaUsageStore : IQuotaUsageStore
{
    private readonly DbContextOptions<SettingsDbContext> _options;

    public SqlQuotaUsageStore(DbContextOptions<SettingsDbContext> options)
    {
        _options = options;
    }

    private SettingsDbContext CreateContext() => new(_options);

    public async Task<QuotaUsage?> GetAsync(QuotaScope scope, CancellationToken ct)
    {
        await using var db = CreateContext();
        var key = scope.ToString();
        return (await db.QuotaUsages.AsNoTracking().FirstOrDefaultAsync(q => q.Scope == key, ct))?.ToUsage();
    }

    public Task<QuotaUsage> AddAsync(QuotaScope scope, QuotaUsageDelta delta, DateTimeOffset now, CancellationToken ct)
    {
        var updated = now.UtcDateTime;
        return ChangeAsync(scope, now,
            rows => rows.ExecuteUpdateAsync(set => set
                .SetProperty(q => q.UsedBytes, q => q.UsedBytes + delta.Bytes)
                .SetProperty(q => q.UsedFiles, q => q.UsedFiles + delta.Files)
                .SetProperty(q => q.UploadedBytes, q => q.UploadedBytes + delta.Uploaded)
                .SetProperty(q => q.DownloadedBytes, q => q.DownloadedBytes + delta.Downloaded)
                .SetProperty(q => q.UpdatedUtc, updated), ct),
            row =>
            {
                row.UsedBytes = delta.Bytes;
                row.UsedFiles = delta.Files;
                row.UploadedBytes = delta.Uploaded;
                row.DownloadedBytes = delta.Downloaded;
            }, ct);
    }

    public Task<QuotaUsage> SetDiskUsageAsync(QuotaScope scope, long usedBytes, long usedFiles, DateTimeOffset scannedAt, CancellationToken ct)
    {
        var scanned = scannedAt.UtcDateTime;
        return ChangeAsync(scope, scannedAt,
            rows => rows.ExecuteUpdateAsync(set => set
                .SetProperty(q => q.UsedBytes, usedBytes)
                .SetProperty(q => q.UsedFiles, usedFiles)
                .SetProperty(q => q.ScannedUtc, scanned)
                .SetProperty(q => q.UpdatedUtc, scanned), ct),
            row =>
            {
                row.UsedBytes = usedBytes;
                row.UsedFiles = usedFiles;
                row.ScannedUtc = scanned;
            }, ct);
    }

    public Task<QuotaUsage> ResetTransferAsync(QuotaScope scope, DateTimeOffset now, CancellationToken ct)
    {
        var updated = now.UtcDateTime;
        return ChangeAsync(scope, now,
            rows => rows.ExecuteUpdateAsync(set => set
                .SetProperty(q => q.UploadedBytes, 0L)
                .SetProperty(q => q.DownloadedBytes, 0L)
                .SetProperty(q => q.UpdatedUtc, updated), ct),
            _ => { }, ct);
    }

    public async Task RemoveAsync(QuotaScope scope, CancellationToken ct)
    {
        await using var db = CreateContext();
        var key = scope.ToString();
        await db.QuotaUsages.Where(q => q.Scope == key).ExecuteDeleteAsync(ct);
    }

    /// <summary>Updates the row in place; inserts it when there is none (and updates it when another node inserted it first).</summary>
    private async Task<QuotaUsage> ChangeAsync(QuotaScope scope, DateTimeOffset now, Func<IQueryable<QuotaUsageRow>, Task<int>> update,
        Action<QuotaUsageRow> initialize, CancellationToken ct)
    {
        var key = scope.ToString();
        for (var attempt = 0; ; attempt++)
        {
            await using var db = CreateContext();
            var rows = db.QuotaUsages.Where(q => q.Scope == key);
            if (await update(rows) == 0)
            {
                var row = new QuotaUsageRow { Scope = key, UpdatedUtc = now.UtcDateTime };
                initialize(row);
                db.QuotaUsages.Add(row);
                try
                {
                    await db.SaveChangesAsync(ct);
                }
                catch (DbUpdateException) when (attempt == 0)
                {
                    continue; // inserted by another node at the same time: update it
                }
            }
            return (await db.QuotaUsages.AsNoTracking().FirstAsync(q => q.Scope == key, ct)).ToUsage();
        }
    }
}
