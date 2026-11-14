using SshServer.Interfaces.Audit;

namespace SshServer.Settings.Sql.Audit;

/// <summary>The audit log of the obsolete LiteDB settings provider: it has no audit table, so nothing is kept.</summary>
public sealed class DisabledAuditLog : IAuditLog
{
    public bool IsEnabled => false;

    public Task AppendAsync(AuditEntry entry, CancellationToken ct) => Task.CompletedTask;

    public Task<AuditQueryResult> QueryAsync(AuditQuery query, CancellationToken ct) => Task.FromResult(new AuditQueryResult([], 0));

    public Task<int> DeleteOlderThanAsync(DateTime cutoffUtc, CancellationToken ct) => Task.FromResult(0);
}
