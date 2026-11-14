namespace SshServer.Interfaces.Webhooks;

/// <summary>
/// The webhooks and their outbox (<see cref="WebhookDelivery"/>) in the settings store. The webhooks plug-in and the
/// admin UI use it through this interface. The returned objects are detached copies.
/// </summary>
public interface IWebhookStore
{
    /// <summary>False when the settings store has no webhook tables (the obsolete LiteDB provider): there are no webhooks.</summary>
    bool IsEnabled { get; }

    Task<IReadOnlyList<Webhook>> ListAsync(CancellationToken ct);

    Task<Webhook?> GetAsync(int id, CancellationToken ct);

    /// <summary>Adds the webhook and sets its <see cref="Webhook.Id"/>. False when the name is already used.</summary>
    Task<bool> AddAsync(Webhook webhook, CancellationToken ct);

    /// <summary>Saves all fields. False when there is no such webhook or the new name is already used.</summary>
    Task<bool> UpdateAsync(Webhook webhook, CancellationToken ct);

    /// <summary>Removes the webhook and its deliveries. False when there is no such webhook.</summary>
    Task<bool> RemoveAsync(int id, CancellationToken ct);

    /// <summary>Adds deliveries to the outbox (new rows, <see cref="WebhookDelivery.Id"/> is set).</summary>
    Task AddDeliveriesAsync(IReadOnlyList<WebhookDelivery> deliveries, CancellationToken ct);

    /// <summary>
    /// Takes at most <paramref name="max"/> pending deliveries that are due, for <paramref name="owner"/>, until
    /// <paramref name="leaseUntilUtc"/>. A delivery that another owner has (with a lease that has not ended) is not
    /// taken, so several nodes can send from one outbox; each claim is atomic.
    /// </summary>
    Task<IReadOnlyList<WebhookDelivery>> ClaimDueAsync(string owner, DateTime nowUtc, DateTime leaseUntilUtc, int max, CancellationToken ct);

    /// <summary>Saves the result of an attempt (status, attempts, times, answer) and ends the lease.</summary>
    Task SaveAttemptAsync(WebhookDelivery delivery, CancellationToken ct);

    /// <summary>Ends the lease without an attempt (the node stops), so the delivery is sent later.</summary>
    Task ReleaseAsync(long id, CancellationToken ct);

    /// <summary>The newest deliveries of a webhook.</summary>
    Task<IReadOnlyList<WebhookDelivery>> ListDeliveriesAsync(int webhookId, int take, CancellationToken ct);

    /// <summary>Makes a finished delivery pending again, due now, with its attempts reset. False: no such (asynchronous) delivery.</summary>
    Task<bool> RedeliverAsync(long id, DateTime nowUtc, CancellationToken ct);

    /// <summary>Removes the finished deliveries (not pending) created before <paramref name="cutoffUtc"/>; returns how many.</summary>
    Task<int> DeleteFinishedOlderThanAsync(DateTime cutoffUtc, CancellationToken ct);
}
