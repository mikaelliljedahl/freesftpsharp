using System.Text.Json;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Webhooks;

namespace SshServer.Webhooks;

/// <summary>
/// The synchronous webhooks: asks each matching webhook, in name order, before an upload, download or delete runs
/// (<see cref="IEventBus.AskAsync"/>). A 2xx answer allows it; a 403 denies it, and the <c>message</c> of the JSON body
/// (or the text body) is shown to the client; any other answer, an error or no answer within the timeout denies it,
/// unless the webhook is <see cref="Webhook.FailOpen"/>. The first deny wins. Each answer is kept in the deliveries
/// list. With no synchronous webhook it allows at once, without a request.
/// </summary>
public sealed class WebhookEventHook : IEventHook
{
    public const int MaxClientMessageLength = 200;

    private readonly WebhookCatalog _catalog;
    private readonly WebhookSender _sender;
    private readonly IWebhookStore _store;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    public WebhookEventHook(WebhookCatalog catalog, WebhookSender sender, IWebhookStore store, TimeProvider time, ILogger<WebhookEventHook> logger)
    {
        _catalog = catalog;
        _sender = sender;
        _store = store;
        _time = time;
        _logger = logger;
    }

    public ValueTask<HookDecision> DecideAsync(IEvent @event, CancellationToken ct)
    {
        if (@event is not FileEvent { IsPreEvent: true } file)
            return ValueTask.FromResult(HookDecision.Allow);
        var loading = _catalog.GetAsync(ct);
        if (!loading.IsCompletedSuccessfully)
            return new ValueTask<HookDecision>(LoadAndDecideAsync(file, loading.AsTask(), ct));
        var snapshot = loading.Result;
        return snapshot.Sync.Count == 0
            ? ValueTask.FromResult(HookDecision.Allow)
            : new ValueTask<HookDecision>(DecideSlowAsync(file, snapshot, ct));
    }

    private async Task<HookDecision> LoadAndDecideAsync(FileEvent file, Task<WebhookCatalogSnapshot> loading, CancellationToken ct)
    {
        var snapshot = await loading;
        return snapshot.Sync.Count == 0 ? HookDecision.Allow : await DecideSlowAsync(file, snapshot, ct);
    }

    private async Task<HookDecision> DecideSlowAsync(FileEvent file, WebhookCatalogSnapshot snapshot, CancellationToken ct)
    {
        var name = EventNames.Of(file);
        string? payload = null;
        var eventId = Guid.NewGuid();
        foreach (var webhook in snapshot.Sync)
        {
            if (!webhook.Matches(file, name))
                continue;

            payload ??= WebhookPayload.Create(file, eventId);
            var delivery = WebhookSink.NewDelivery(webhook.Id, eventId, name, payload, _time.GetUtcNow().UtcDateTime);
            delivery.Sync = true;
            var response = await _sender.SendAsync(webhook, delivery.DeliveryId, name, WebhookPayload.WithAttempt(payload, 1), ct);
            await RecordAsync(delivery, response);

            if (response.IsSuccess)
                continue;
            if (response.StatusCode == 403)
            {
                var message = ClientMessage(response.Body);
                return HookDecision.Deny($"The webhook {webhook.Name} refused it" + (message == null ? "." : $": {message}"), message);
            }
            if (webhook.Definition.FailOpen)
            {
                _logger.LogWarning("The webhook {Webhook} failed on {Event} {Path} ({Error}); it fails open, so the operation runs.",
                    webhook.Name, name, file.VirtualPath, response.Describe());
                continue;
            }
            _logger.LogWarning("The webhook {Webhook} failed on {Event} {Path} ({Error}); the operation is refused.",
                webhook.Name, name, file.VirtualPath, response.Describe());
            return HookDecision.Deny($"The webhook {webhook.Name} failed: {response.Describe()}");
        }
        return HookDecision.Allow;
    }

    private async Task RecordAsync(WebhookDelivery delivery, WebhookResponse response)
    {
        // 2xx and 403 are answers of the receiver: delivered. The rest failed. A synchronous delivery is never sent again.
        delivery.Status = response.IsSuccess || response.StatusCode == 403 ? WebhookDeliveryStatus.Delivered : WebhookDeliveryStatus.Failed;
        delivery.Attempts = 1;
        delivery.LastAttemptUtc = delivery.CreatedUtc;
        delivery.NextAttemptUtc = null;
        delivery.LastStatusCode = response.StatusCode;
        delivery.LastError = response.IsSuccess ? null : response.Describe();
        delivery.ResponseExcerpt = response.Body;
        try
        {
            await _store.AddDeliveriesAsync([delivery], CancellationToken.None);
        }
        catch (Exception ex)
        {
            // The answer counts, also when the record cannot be written.
            _logger.LogError(ex, "The delivery of the synchronous webhook {WebhookId} could not be recorded.", delivery.WebhookId);
        }
    }

    /// <summary>The <c>message</c> of a JSON body, else the text body; one line, without control characters, at most 200 characters.</summary>
    internal static string? ClientMessage(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return null;
        var text = body.Trim();
        if (text.StartsWith('{'))
        {
            try
            {
                using var json = JsonDocument.Parse(text);
                text = json.RootElement.TryGetProperty("message", out var message) && message.ValueKind == JsonValueKind.String
                    ? message.GetString() ?? string.Empty
                    : string.Empty;
            }
            catch (JsonException)
            {
                // Not JSON after all: the text as it is.
            }
        }
        var clean = new string(text.Select(c => char.IsControl(c) ? ' ' : c).ToArray()).Trim();
        if (clean.Length > MaxClientMessageLength)
            clean = clean[..MaxClientMessageLength];
        return clean.Length == 0 ? null : clean;
    }
}
