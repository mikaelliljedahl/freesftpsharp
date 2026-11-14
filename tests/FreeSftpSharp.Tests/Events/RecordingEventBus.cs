using System.Collections.Concurrent;
using SshServer.Interfaces.Events;

namespace FreeSftpSharp.Tests.Events;

/// <summary>A synchronous <see cref="IEventBus"/> for the decorator tests: it keeps the published events and answers with <see cref="Decide"/>.</summary>
public sealed class RecordingEventBus : IEventBus
{
    private readonly ConcurrentQueue<IEvent> _published = new();
    private readonly ConcurrentQueue<IEvent> _asked = new();

    public Func<IEvent, HookDecision> Decide { get; set; } = _ => HookDecision.Allow;

    public IReadOnlyList<IEvent> Published => _published.ToArray();

    public IReadOnlyList<IEvent> Asked => _asked.ToArray();

    public IReadOnlyList<FileEvent> FileEvents => Published.OfType<FileEvent>().ToList();

    public ValueTask PublishAsync(IEvent @event, CancellationToken ct = default)
    {
        _published.Enqueue(@event);
        return ValueTask.CompletedTask;
    }

    public Task<HookDecision> AskAsync(IEvent @event, CancellationToken ct = default)
    {
        _asked.Enqueue(@event);
        return Task.FromResult(Decide(@event));
    }
}
