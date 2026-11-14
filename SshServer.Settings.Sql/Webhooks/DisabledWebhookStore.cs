using SshServer.Interfaces.Webhooks;

namespace SshServer.Settings.Sql.Webhooks;

/// <summary>The webhook store of the obsolete LiteDB settings provider: it has no webhook tables, so there are no webhooks.</summary>
public sealed class DisabledWebhookStore : IWebhookStore
{
    public bool IsEnabled => false;

    public Task<IReadOnlyList<Webhook>> ListAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<Webhook>>([]);

    public Task<Webhook?> GetAsync(int id, CancellationToken ct) => Task.FromResult<Webhook?>(null);

    public Task<bool> AddAsync(Webhook webhook, CancellationToken ct) => Task.FromResult(false);

    public Task<bool> UpdateAsync(Webhook webhook, CancellationToken ct) => Task.FromResult(false);

    public Task<bool> RemoveAsync(int id, CancellationToken ct) => Task.FromResult(false);

    public Task AddDeliveriesAsync(IReadOnlyList<WebhookDelivery> deliveries, CancellationToken ct) => Task.CompletedTask;

    public Task<IReadOnlyList<WebhookDelivery>> ClaimDueAsync(string owner, DateTime nowUtc, DateTime leaseUntilUtc, int max, CancellationToken ct)
        => Task.FromResult<IReadOnlyList<WebhookDelivery>>([]);

    public Task SaveAttemptAsync(WebhookDelivery delivery, CancellationToken ct) => Task.CompletedTask;

    public Task ReleaseAsync(long id, CancellationToken ct) => Task.CompletedTask;

    public Task<IReadOnlyList<WebhookDelivery>> ListDeliveriesAsync(int webhookId, int take, CancellationToken ct)
        => Task.FromResult<IReadOnlyList<WebhookDelivery>>([]);

    public Task<bool> RedeliverAsync(long id, DateTime nowUtc, CancellationToken ct) => Task.FromResult(false);

    public Task<int> DeleteFinishedOlderThanAsync(DateTime cutoffUtc, CancellationToken ct) => Task.FromResult(0);
}
