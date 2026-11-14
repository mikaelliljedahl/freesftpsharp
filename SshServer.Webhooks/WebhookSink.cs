using SshServer.Interfaces.Events;
using SshServer.Interfaces.Webhooks;

namespace SshServer.Webhooks;

/// <summary>
/// The event sink of the asynchronous webhooks: writes one outbox row per matching webhook and wakes the dispatcher.
/// It runs on its own queue of the event bus, so a slow or dead endpoint never delays a transfer; with no webhook it
/// returns at once.
/// </summary>
public sealed class WebhookSink : IEventSink
{
    private readonly WebhookCatalog _catalog;
    private readonly IWebhookStore _store;
    private readonly WebhookDispatchSignal _signal;
    private readonly TimeProvider _time;

    public WebhookSink(WebhookCatalog catalog, IWebhookStore store, WebhookDispatchSignal signal, TimeProvider time)
    {
        _catalog = catalog;
        _store = store;
        _signal = signal;
        _time = time;
    }

    public async ValueTask HandleAsync(IEvent @event, CancellationToken ct)
    {
        var snapshot = await _catalog.GetAsync(ct);
        if (snapshot.Async.Count == 0)
            return;

        var name = WebhookEventNames.Of(@event);
        var matching = snapshot.Async.Where(w => w.Matches(@event, name)).ToArray();
        if (matching.Length == 0)
            return;

        var eventId = Guid.NewGuid();
        var payload = WebhookPayload.Create(@event, eventId);
        var now = _time.GetUtcNow().UtcDateTime;
        var deliveries = matching.Select(w => NewDelivery(w.Id, eventId, name, payload, now)).ToArray();
        await _store.AddDeliveriesAsync(deliveries, ct);
        _signal.Notify();
    }

    /// <summary>A pending delivery, due now.</summary>
    public static WebhookDelivery NewDelivery(int webhookId, Guid eventId, string eventName, string payload, DateTime nowUtc) => new()
    {
        DeliveryId = Guid.NewGuid(),
        WebhookId = webhookId,
        EventId = eventId,
        EventType = eventName,
        Payload = payload,
        Status = WebhookDeliveryStatus.Pending,
        CreatedUtc = nowUtc,
        NextAttemptUtc = nowUtc,
    };
}
