namespace SshServer.Interfaces.Events;

/// <summary>
/// A consumer of every published event, for example the audit log, a webhook or metrics. Register it as a singleton
/// <c>IEventSink</c>. A sink gets the events one after the other, in the order they were published, on its own
/// background task: it can be slow or throw without effect on the transfers or on the other sinks.
/// </summary>
public interface IEventSink
{
    ValueTask HandleAsync(IEvent @event, CancellationToken ct);
}

/// <summary>
/// Decides synchronously whether the operation of a <c>Pre*</c> event may run (<see cref="IEventBus.AskAsync"/>).
/// The operation waits for the answer, so a hook must be fast. Register it as a singleton <c>IEventHook</c>.
/// </summary>
public interface IEventHook
{
    ValueTask<HookDecision> DecideAsync(IEvent @event, CancellationToken ct);
}
