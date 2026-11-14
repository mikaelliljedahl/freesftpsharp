namespace SshServer.Interfaces.Events;

/// <summary>
/// The one event stream of the server (docs/ARCHITECTURE.md, "Plug-in points"). Producers publish here; the consumers
/// are the registered <see cref="IEventSink"/> and <see cref="IEventHook"/> services.
/// </summary>
public interface IEventBus
{
    /// <summary>
    /// Queues the event for every <see cref="IEventSink"/> and returns. The sinks run in the background, each on its
    /// own, so a slow or failing sink never delays the caller. Nothing is dropped: only when the queue of a sink is
    /// full, the call waits for space.
    /// </summary>
    ValueTask PublishAsync(IEvent @event, CancellationToken ct = default);

    /// <summary>
    /// Asks every <see cref="IEventHook"/>, in registration order, whether the operation of a <c>Pre*</c> event may
    /// run. The first <see cref="HookDecision.Deny"/> wins and the other hooks are not asked. A hook that throws
    /// denies the operation. The event is not published; the producer publishes it with the result.
    /// </summary>
    Task<HookDecision> AskAsync(IEvent @event, CancellationToken ct = default);
}

/// <summary>The answer of an <see cref="IEventHook"/>.</summary>
public sealed record HookDecision
{
    private HookDecision(bool isDenied, string? message, string? clientMessage)
    {
        IsDenied = isDenied;
        Message = message;
        ClientMessage = clientMessage;
    }

    /// <summary>The operation may run.</summary>
    public static HookDecision Allow { get; } = new(false, null, null);

    /// <summary>The operation is refused. The protocol answers "permission denied" (SFTP: SSH_FX_PERMISSION_DENIED).</summary>
    /// <param name="message">Why, for the audit log and the server log.</param>
    /// <param name="clientMessage">A short text that the protocol adds to its "permission denied" answer; null: none.</param>
    public static HookDecision Deny(string message, string? clientMessage = null) => new(true, message, clientMessage);

    public bool IsDenied { get; }

    /// <summary>Why the operation is refused; for the audit log and the server log.</summary>
    public string? Message { get; }

    /// <summary>The text for the client, for example the message of a pre-upload webhook; null: the client gets only "permission denied".</summary>
    public string? ClientMessage { get; }
}
