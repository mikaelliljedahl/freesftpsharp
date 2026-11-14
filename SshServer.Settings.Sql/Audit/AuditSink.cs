using SshServer.Interfaces.Audit;
using SshServer.Interfaces.Events;

namespace SshServer.Settings.Sql.Audit;

/// <summary>
/// Writes every event to the audit log, except <see cref="FileEventType.FirstUpload"/>: it repeats the
/// <see cref="FileEventType.Upload"/> of the same file, which is in the log.
/// </summary>
public sealed class AuditSink : IEventSink
{
    private readonly IAuditLog _log;

    public AuditSink(IAuditLog log)
    {
        _log = log;
    }

    public async ValueTask HandleAsync(IEvent @event, CancellationToken ct)
    {
        if (@event is FileEvent { Type: FileEventType.FirstUpload })
            return;
        await _log.AppendAsync(AuditEntryMapper.From(@event), ct);
    }
}
