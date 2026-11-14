using System.Collections.Concurrent;
using SshServer.Interfaces.Events;

namespace FreeSftpSharp.Tests.Events;

/// <summary>An <see cref="IEventSink"/> that keeps every event in memory, for the tests.</summary>
public sealed class RecordingEventSink : IEventSink
{
    private readonly ConcurrentQueue<IEvent> _events = new();

    public IReadOnlyList<IEvent> Events => _events.ToArray();

    public ValueTask HandleAsync(IEvent @event, CancellationToken ct)
    {
        _events.Enqueue(@event);
        return ValueTask.CompletedTask;
    }

    public IReadOnlyList<T> Of<T>(Func<T, bool>? predicate = null) where T : IEvent
        => Events.OfType<T>().Where(e => predicate == null || predicate(e)).ToList();

    /// <summary>Waits until at least <paramref name="count"/> matching events are here; returns them.</summary>
    public async Task<IReadOnlyList<T>> WaitForAsync<T>(Func<T, bool> predicate, int count = 1, TimeSpan? timeout = null) where T : IEvent
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));
        while (true)
        {
            var found = Of(predicate);
            if (found.Count >= count)
                return found;
            if (DateTime.UtcNow > deadline)
                throw new TimeoutException($"Expected {count} {typeof(T).Name} event(s), got {found.Count}. All events: {string.Join("; ", Events)}");
            await Task.Delay(10);
        }
    }
}

/// <summary>An <see cref="IEventSink"/> that blocks on every event until it is released or canceled.</summary>
public sealed class BlockingEventSink : IEventSink
{
    private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _handled;

    /// <summary>Completes when the sink got its first event.</summary>
    public Task Entered => _entered.Task;

    /// <summary>The events it has finished.</summary>
    public int Handled => Volatile.Read(ref _handled);

    public void Release() => _release.TrySetResult();

    public async ValueTask HandleAsync(IEvent @event, CancellationToken ct)
    {
        _entered.TrySetResult();
        await _release.Task.WaitAsync(ct);
        Interlocked.Increment(ref _handled);
    }
}

/// <summary>An <see cref="IEventSink"/> that throws on every event.</summary>
public sealed class ThrowingEventSink : IEventSink
{
    public ValueTask HandleAsync(IEvent @event, CancellationToken ct) => throw new InvalidOperationException("sink failure for a test");
}

/// <summary>An <see cref="IEventHook"/> with a decision function; it counts the questions.</summary>
public sealed class DelegateEventHook(Func<IEvent, HookDecision> decide) : IEventHook
{
    private int _asked;

    public int Asked => Volatile.Read(ref _asked);

    public ValueTask<HookDecision> DecideAsync(IEvent @event, CancellationToken ct)
    {
        Interlocked.Increment(ref _asked);
        return ValueTask.FromResult(decide(@event));
    }
}
