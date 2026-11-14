using SshServer.Interfaces.Events;

namespace SshServer.EventRules;

/// <summary>
/// The event sink of the rules on events: queues one run per matching rule for the <see cref="EventRuleWorker"/>. With
/// no rule it returns at once (no database read). The events of the actions of a rule never start a rule.
/// </summary>
public sealed class EventRuleSink : IEventSink
{
    private readonly EventRuleCatalog _catalog;
    private readonly EventRuleQueue _queue;

    public EventRuleSink(EventRuleCatalog catalog, EventRuleQueue queue)
    {
        _catalog = catalog;
        _queue = queue;
    }

    public async ValueTask HandleAsync(IEvent @event, CancellationToken ct)
    {
        var snapshot = await _catalog.GetAsync(ct);
        if (snapshot.EventRules.Count == 0 || EventRuleRunner.IsFromAnAction(@event))
            return;

        var name = EventNames.Of(@event);
        foreach (var rule in snapshot.EventRules)
        {
            if (rule.Matches(@event, name))
                await _queue.EnqueueAsync(rule.Definition, @event, ct);
        }
    }
}
