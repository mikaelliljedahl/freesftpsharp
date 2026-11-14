namespace SshServer.Interfaces.Audit;

/// <summary>
/// Who makes the changes of the current call flow (#134), for the <see cref="Events.ProviderEvent.Actor"/> of the
/// settings repository. The repository is a singleton that does not know the administrator of a circuit or a REST API
/// request; the caller that knows it (<c>AdminScopedSettingsRepository</c> for the admin UI and the API, the web client
/// for the changes of users themselves) sets it with <see cref="Begin"/> around the call. Without it, the change is made
/// by the server itself (<see cref="System"/>): the command line, the logins, the jobs and the event rules.
/// <para>
/// The value flows with the call (an <see cref="AsyncLocal{T}"/>), so two circuits or requests at the same time never see
/// the actor of the other. One instance per host (a singleton).
/// </para>
/// </summary>
public sealed class AuditActorContext
{
    /// <summary>The actor of a change that no administrator or user made.</summary>
    public const string System = "system";

    private readonly AsyncLocal<string?> _actor = new();

    /// <summary>The actor now: the innermost <see cref="Begin"/>, else <see cref="System"/>.</summary>
    public string Current => _actor.Value ?? System;

    /// <summary>Sets the actor until the result is disposed; then the previous actor is back.</summary>
    public IDisposable Begin(string actor)
    {
        ArgumentException.ThrowIfNullOrEmpty(actor);
        var previous = _actor.Value;
        _actor.Value = actor;
        return new Scope(this, previous);
    }

    private sealed class Scope : IDisposable
    {
        private readonly AuditActorContext _context;
        private readonly string? _previous;
        private bool _disposed;

        public Scope(AuditActorContext context, string? previous)
        {
            _context = context;
            _previous = previous;
        }

        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            _context._actor.Value = _previous;
        }
    }
}
