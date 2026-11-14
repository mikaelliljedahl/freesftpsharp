using System.Threading.Channels;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;

namespace SshServer.EventRules;

/// <summary>A rule to run for an event; with a completion, a caller waits for the run (a <c>Pre*</c> event).</summary>
public sealed record EventRuleJob(EventRule Rule, IEvent Event, TaskCompletionSource<EventRuleRun>? Completion = null);

/// <summary>
/// The rule runs between the event bus (<see cref="EventRuleSink"/>, <see cref="EventRuleHook"/>) and the
/// <see cref="EventRuleWorker"/>. It keeps the bus free of the dependencies of the actions (the storage, the users), and
/// a slow action never delays an event sink.
/// </summary>
public sealed class EventRuleQueue
{
    public const int Capacity = 10_000;

    private readonly Channel<EventRuleJob> _background = Channel.CreateBounded<EventRuleJob>(new BoundedChannelOptions(Capacity)
    {
        FullMode = BoundedChannelFullMode.Wait,
        SingleReader = true,
    });

    private readonly Channel<EventRuleJob> _waiting = Channel.CreateUnbounded<EventRuleJob>(new UnboundedChannelOptions { SingleReader = true });

    /// <summary>The runs of the events after the operation.</summary>
    public ChannelReader<EventRuleJob> Background => _background.Reader;

    /// <summary>The runs that a caller waits for.</summary>
    public ChannelReader<EventRuleJob> Waiting => _waiting.Reader;

    /// <summary>Queues a run; waits only when the queue is full.</summary>
    public ValueTask EnqueueAsync(EventRule rule, IEvent @event, CancellationToken ct) => _background.Writer.WriteAsync(new EventRuleJob(rule, @event), ct);

    /// <summary>Queues a run and waits for its result.</summary>
    public async Task<EventRuleRun> RunAndWaitAsync(EventRule rule, IEvent @event, CancellationToken ct)
    {
        var completion = new TaskCompletionSource<EventRuleRun>(TaskCreationOptions.RunContinuationsAsynchronously);
        await _waiting.Writer.WriteAsync(new EventRuleJob(rule, @event, completion), ct);
        return await completion.Task.WaitAsync(ct);
    }
}
