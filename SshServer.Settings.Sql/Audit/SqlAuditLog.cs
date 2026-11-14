using Microsoft.EntityFrameworkCore;
using SshServer.Interfaces.Audit;

namespace SshServer.Settings.Sql.Audit;

/// <summary>
/// <see cref="IAuditLog"/> in the table AuditEntries of the settings database. The settings repository creates and
/// migrates the database at the start; this class only reads and writes rows, each call with its own context.
/// </summary>
public sealed class SqlAuditLog : IAuditLog
{
    /// <summary>The most rows one query returns (the CSV export asks for this many).</summary>
    public const int MaxTake = 100_000;

    private readonly DbContextOptions<SettingsDbContext> _options;

    public SqlAuditLog(DbContextOptions<SettingsDbContext> options)
    {
        _options = options;
    }

    public bool IsEnabled => true;

    public async Task AppendAsync(AuditEntry entry, CancellationToken ct)
    {
        await using var db = new SettingsDbContext(_options);
        entry.Id = 0;
        db.AuditEntries.Add(entry);
        await db.SaveChangesAsync(ct);
    }

    public async Task<AuditQueryResult> QueryAsync(AuditQuery query, CancellationToken ct)
    {
        await using var db = new SettingsDbContext(_options);
        var rows = db.AuditEntries.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(query.Username))
        {
            var username = query.Username.Trim().ToLowerInvariant();
            rows = rows.Where(a => a.Username != null && a.Username.ToLower() == username);
        }
        if (!string.IsNullOrWhiteSpace(query.Type))
            rows = rows.Where(a => a.Type == query.Type);
        if (!string.IsNullOrWhiteSpace(query.Status))
            rows = rows.Where(a => a.Status == query.Status);
        if (query.FromUtc is { } from)
            rows = rows.Where(a => a.TimestampUtc >= from);
        if (query.ToUtc is { } to)
            rows = rows.Where(a => a.TimestampUtc < to);

        var total = await rows.CountAsync(ct);
        var entries = await rows
            .OrderByDescending(a => a.TimestampUtc).ThenByDescending(a => a.Id)
            .Skip(Math.Max(0, query.Skip))
            .Take(Math.Clamp(query.Take, 0, MaxTake))
            .ToListAsync(ct);
        return new AuditQueryResult(entries, total);
    }

    public async Task<int> DeleteOlderThanAsync(DateTime cutoffUtc, CancellationToken ct)
    {
        await using var db = new SettingsDbContext(_options);
        return await db.AuditEntries.Where(a => a.TimestampUtc < cutoffUtc).ExecuteDeleteAsync(ct);
    }
}
