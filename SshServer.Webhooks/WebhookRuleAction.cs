using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Webhooks;

namespace SshServer.Webhooks;

/// <summary>
/// The "Webhook" action of the event rules (#68): puts the event of the rule in the outbox of a webhook, so the
/// <see cref="WebhookDispatcher"/> sends it with its signature, retries and delivery history. The webhook filters are
/// not used; a webhook with <see cref="Webhook.OnlyForEventRules"/> gets only these events. A scheduled or on-demand run
/// sends a <c>System.ScheduledJobRan</c> event. The payload has the field <c>rule</c> with the name of the rule.
/// </summary>
public sealed class WebhookRuleAction : IEventRuleAction
{
    public const string WebhookKey = "Webhook";

    private readonly WebhookCatalog _catalog;
    private readonly IWebhookStore _store;
    private readonly WebhookDispatchSignal _signal;
    private readonly TimeProvider _time;

    public WebhookRuleAction(WebhookCatalog catalog, IWebhookStore store, WebhookDispatchSignal signal, TimeProvider time)
    {
        _catalog = catalog;
        _store = store;
        _signal = signal;
        _time = time;
    }

    public string Type => "Webhook";

    public string DisplayName => "Webhook";

    public string Description => "Sends the event to a webhook of the Webhooks page, with its signature and retries.";

    public bool NeedsUser => false;

    public IReadOnlyList<EventActionField> Fields { get; } =
    [
        new(WebhookKey, "Webhook", EventActionFieldKind.Text) { Help = "The name of an enabled webhook." },
    ];

    public IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options)
        => options.TryGetValue(WebhookKey, out var name) && !string.IsNullOrWhiteSpace(name) ? [] : ["Enter the name of a webhook."];

    public async Task<EventActionResult> ExecuteAsync(EventActionContext context, CancellationToken ct)
    {
        var name = context.Option(WebhookKey).Trim();
        var webhook = (await _catalog.GetAsync(ct)).Find(name) ?? (await _catalog.ReloadAsync(ct)).Find(name);
        if (webhook == null)
            return EventActionResult.Failed($"There is no enabled webhook {name}.");

        var now = _time.GetUtcNow();
        var @event = context.Event ?? new SystemEvent(SystemEventType.ScheduledJobRan)
        {
            Timestamp = now,
            Source = "EventRules",
            Message = $"The event rule {context.Rule.Name} ran.",
        };
        var eventId = Guid.NewGuid();
        var payload = WebhookPayload.WithRule(WebhookPayload.Create(@event, eventId), context.Rule.Name);
        await _store.AddDeliveriesAsync([WebhookSink.NewDelivery(webhook.Id, eventId, EventNames.Of(@event), payload, now.UtcDateTime)], ct);
        _signal.Notify();
        return EventActionResult.Ok($"Queued for the webhook {webhook.Name}.");
    }
}
