using SshServer.Interfaces.Audit;

namespace FreeSftpSharp.Tests.Infrastructure;

/// <summary>An <see cref="IAuditLog"/> in memory, with the same filters as the SQL one, for the UI tests.</summary>
public sealed class InMemoryAuditLog : IAuditLog
{
    private readonly List<AuditEntry> _entries = new();
    private long _nextId;

    public bool IsEnabled { get; set; } = true;

    public Task AppendAsync(AuditEntry entry, CancellationToken ct)
    {
        lock (_entries)
        {
            entry.Id = ++_nextId;
            _entries.Add(entry);
        }
        return Task.CompletedTask;
    }

    public Task<AuditQueryResult> QueryAsync(AuditQuery query, CancellationToken ct)
    {
        lock (_entries)
        {
            var rows = _entries.Where(a =>
                (query.Username == null || string.Equals(a.Username, query.Username, StringComparison.OrdinalIgnoreCase))
                && (query.Type == null || a.Type == query.Type)
                && (query.Status == null || a.Status == query.Status)
                && (query.FromUtc == null || a.TimestampUtc >= query.FromUtc)
                && (query.ToUtc == null || a.TimestampUtc < query.ToUtc))
                .OrderByDescending(a => a.TimestampUtc).ThenByDescending(a => a.Id).ToList();
            return Task.FromResult(new AuditQueryResult(rows.Skip(query.Skip).Take(query.Take).ToList(), rows.Count));
        }
    }

    public Task<int> DeleteOlderThanAsync(DateTime cutoffUtc, CancellationToken ct)
    {
        lock (_entries)
            return Task.FromResult(_entries.RemoveAll(a => a.TimestampUtc < cutoffUtc));
    }
}
