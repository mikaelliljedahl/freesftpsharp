using Microsoft.Extensions.Options;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;

namespace SshServer.EventRules;

/// <summary>
/// The hook of the rules on <c>Pre*</c> events: the upload, download or delete waits until the matching rules ran, and a
/// rule run that fails (or does not end within <see cref="EventRuleOptions.SyncTimeoutSeconds"/>) refuses it. With no
/// such rule it allows at once.
/// </summary>
public sealed class EventRuleHook : IEventHook
{
    private readonly EventRuleCatalog _catalog;
    private readonly EventRuleQueue _queue;
    private readonly TimeSpan _timeout;

    public EventRuleHook(EventRuleCatalog catalog, EventRuleQueue queue, IOptions<EventRuleOptions> options)
    {
        _catalog = catalog;
        _queue = queue;
        _timeout = TimeSpan.FromSeconds(options.Value.SyncTimeoutSeconds);
    }

    public async ValueTask<HookDecision> DecideAsync(IEvent @event, CancellationToken ct)
    {
        var snapshot = await _catalog.GetAsync(ct);
        if (snapshot.PreEventRules.Count == 0 || EventRuleRunner.IsFromAnAction(@event))
            return HookDecision.Allow;

        var name = EventNames.Of(@event);
        foreach (var rule in snapshot.PreEventRules)
        {
            if (!rule.Matches(@event, name))
                continue;

            EventRuleRun run;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(_timeout); // wall-clock time: the actions do I/O
            try
            {
                run = await _queue.RunAndWaitAsync(rule.Definition, @event, timeout.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return HookDecision.Deny($"The event rule {rule.Name} did not end within {_timeout.TotalSeconds} s.");
            }
            if (run.Status == EventRuleRunStatus.Failed)
                return HookDecision.Deny($"The event rule {rule.Name} refused it: {run.Message}", $"refused by the rule {rule.Name}");
        }
        return HookDecision.Allow;
    }
}
