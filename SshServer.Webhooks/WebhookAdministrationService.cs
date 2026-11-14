using Microsoft.Extensions.Options;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Webhooks;

namespace SshServer.Webhooks;

/// <summary>The result of <see cref="WebhookAdministrationService.SaveAsync"/>.</summary>
public sealed record WebhookSaveResult(bool Succeeded, int? Id, IReadOnlyList<string> Errors)
{
    public static WebhookSaveResult Failed(params string[] errors) => new(false, null, errors);
}

/// <summary>A webhook without its secret and header values, for the provider events.</summary>
public sealed record WebhookSnapshot(string Name, string Url, string Method, bool HasSecret, IReadOnlyList<string> HeaderNames,
    IReadOnlyList<string> EventTypes, IReadOnlyList<string> Users, string? PathGlob, bool Sync, bool FailOpen, int TimeoutSeconds, bool Enabled,
    bool OnlyForEventRules)
{
    public static WebhookSnapshot From(Webhook w) => new(w.Name, w.Url, w.Method, !string.IsNullOrEmpty(w.ProtectedSecret),
        w.Headers.Keys.ToArray(), [.. w.EventTypes], [.. w.Users], w.PathGlob, w.Sync, w.FailOpen, w.TimeoutSeconds, w.Enabled,
        w.OnlyForEventRules);
}

/// <summary>
/// The one application service for webhooks: the admin UI (and later the REST API, #67) uses it. It checks the rules,
/// encrypts the secret, saves, reloads the catalog, publishes the provider events, sends a test event and redelivers.
/// Every call needs <see cref="AdminPermissions.ManageEvents"/> of the <see cref="AdminActor"/> (#112): the page policy
/// is not the only check.
/// </summary>
public sealed class WebhookAdministrationService
{
    public const int DeliveriesPageSize = 50;

    private readonly IWebhookStore _store;
    private readonly WebhookCatalog _catalog;
    private readonly WebhookSecretProtector _protector;
    private readonly WebhookDispatchSignal _signal;
    private readonly WebhookOptions _options;
    private readonly TimeProvider _time;
    private readonly IEventBus? _events;

    public WebhookAdministrationService(IWebhookStore store, WebhookCatalog catalog, WebhookSecretProtector protector, WebhookDispatchSignal signal,
        IOptions<WebhookOptions> options, TimeProvider time, IEventBus? events = null)
    {
        _store = store;
        _catalog = catalog;
        _protector = protector;
        _signal = signal;
        _options = options.Value;
        _time = time;
        _events = events;
    }

    /// <summary>False with the obsolete LiteDB settings provider: it has no webhooks.</summary>
    public bool IsEnabled => _store.IsEnabled;

    public bool AllowInsecureWebhooks => _options.AllowInsecureWebhooks;

    public Task<IReadOnlyList<Webhook>> ListAsync(AdminActor actor, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageEvents);
        return _store.ListAsync(ct);
    }

    public Task<Webhook?> GetAsync(AdminActor actor, int id, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageEvents);
        return _store.GetAsync(id, ct);
    }

    public async Task<WebhookSaveResult> SaveAsync(AdminActor actor, WebhookInput input, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageEvents);
        if (!_store.IsEnabled)
            return WebhookSaveResult.Failed("Webhooks need the SQLite settings database.");
        var errors = WebhookValidator.Validate(input, _options);
        if (errors.Count > 0)
            return new WebhookSaveResult(false, null, errors);

        Webhook webhook;
        Webhook? before = null;
        if (input.Id is { } id)
        {
            before = await _store.GetAsync(id, ct);
            if (before == null)
                return WebhookSaveResult.Failed("The webhook does not exist any more.");
            webhook = await _store.GetAsync(id, ct) ?? before;
        }
        else
        {
            webhook = new Webhook();
        }

        webhook.Name = input.Name.Trim();
        webhook.Url = input.Url.Trim();
        webhook.Method = input.Method;
        webhook.Headers = input.Headers.ToDictionary(h => h.Key.Trim(), h => h.Value.Trim());
        webhook.EventTypes = input.EventTypes.Select(EventNames.Canonical).Distinct().ToList();
        webhook.Users = input.Users.Select(u => u.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        webhook.PathGlob = string.IsNullOrWhiteSpace(input.PathGlob) ? null : input.PathGlob.Trim();
        webhook.Sync = input.Sync;
        webhook.FailOpen = input.Sync && input.FailOpen;
        webhook.TimeoutSeconds = input.TimeoutSeconds;
        webhook.Enabled = input.Enabled;
        webhook.OnlyForEventRules = input.OnlyForEventRules;
        if (!string.IsNullOrEmpty(input.NewSecret))
            webhook.ProtectedSecret = _protector.Protect(input.NewSecret);
        else if (input.RemoveSecret)
            webhook.ProtectedSecret = null;

        var saved = before == null ? await _store.AddAsync(webhook, ct) : await _store.UpdateAsync(webhook, ct);
        if (!saved)
            return WebhookSaveResult.Failed($"A webhook with the name {webhook.Name} already exists.");

        await _catalog.ReloadAsync(ct);
        await PublishAsync(actor, before == null ? ProviderAction.Add : ProviderAction.Update, webhook, ChangedFields(before, webhook), ct);
        return new WebhookSaveResult(true, webhook.Id, []);
    }

    public async Task<bool> RemoveAsync(AdminActor actor, int id, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageEvents);
        var webhook = await _store.GetAsync(id, ct);
        if (webhook == null || !await _store.RemoveAsync(id, ct))
            return false;
        await _catalog.ReloadAsync(ct);
        await PublishAsync(actor, ProviderAction.Delete, webhook, [], ct);
        return true;
    }

    /// <summary>Puts a test event for this webhook in the outbox (also for a disabled or synchronous one). False: no such webhook.</summary>
    public async Task<bool> SendTestAsync(AdminActor actor, int id, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageEvents);
        var webhook = await _store.GetAsync(id, ct);
        if (webhook == null)
            return false;
        var now = _time.GetUtcNow();
        var test = new WebhookTestEvent(webhook.Name) { Timestamp = now };
        var eventId = Guid.NewGuid();
        await _store.AddDeliveriesAsync([WebhookSink.NewDelivery(webhook.Id, eventId, EventNames.Of(test), WebhookPayload.Create(test, eventId), now.UtcDateTime)], ct);
        if (!webhook.Enabled)
            return true; // the dispatcher makes it a dead letter: "disabled"
        _signal.Notify();
        return true;
    }

    public Task<IReadOnlyList<WebhookDelivery>> ListDeliveriesAsync(AdminActor actor, int webhookId, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageEvents);
        return _store.ListDeliveriesAsync(webhookId, DeliveriesPageSize, ct);
    }

    /// <summary>Sends an asynchronous delivery again, now, with new attempts.</summary>
    public async Task<bool> RedeliverAsync(AdminActor actor, long deliveryId, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageEvents);
        if (!await _store.RedeliverAsync(deliveryId, _time.GetUtcNow().UtcDateTime, ct))
            return false;
        _signal.Notify();
        return true;
    }

    private static IReadOnlyList<string> ChangedFields(Webhook? before, Webhook after)
    {
        if (before == null)
            return [];
        var changed = new List<string>();
        void Check(string name, bool same)
        {
            if (!same)
                changed.Add(name);
        }
        Check(nameof(Webhook.Name), before.Name == after.Name);
        Check(nameof(Webhook.Url), before.Url == after.Url);
        Check(nameof(Webhook.Method), before.Method == after.Method);
        Check("Secret", before.ProtectedSecret == after.ProtectedSecret);
        Check(nameof(Webhook.Headers), before.Headers.Count == after.Headers.Count && !before.Headers.Except(after.Headers).Any());
        Check(nameof(Webhook.EventTypes), before.EventTypes.SequenceEqual(after.EventTypes));
        Check(nameof(Webhook.Users), before.Users.SequenceEqual(after.Users));
        Check(nameof(Webhook.PathGlob), before.PathGlob == after.PathGlob);
        Check(nameof(Webhook.Sync), before.Sync == after.Sync);
        Check(nameof(Webhook.FailOpen), before.FailOpen == after.FailOpen);
        Check(nameof(Webhook.TimeoutSeconds), before.TimeoutSeconds == after.TimeoutSeconds);
        Check(nameof(Webhook.Enabled), before.Enabled == after.Enabled);
        Check(nameof(Webhook.OnlyForEventRules), before.OnlyForEventRules == after.OnlyForEventRules);
        return changed;
    }

    private async Task PublishAsync(AdminActor actor, ProviderAction action, Webhook webhook, IReadOnlyList<string> changed, CancellationToken ct)
    {
        if (_events == null)
            return;
        await _events.PublishAsync(new ProviderEvent(action, ProviderObjectType.Webhook, webhook.Name)
        {
            Timestamp = _time.GetUtcNow(),
            Actor = actor.AuditName,
            Object = WebhookSnapshot.From(webhook),
            ChangedFields = changed,
        }, ct);
    }
}
