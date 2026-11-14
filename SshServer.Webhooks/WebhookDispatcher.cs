using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Webhooks;

namespace SshServer.Webhooks;

/// <summary>
/// Sends the outbox in the background: takes the due deliveries with a lease (so several nodes can share the outbox, and
/// a node that stops gives its deliveries back), sends at most <see cref="WebhookOptions.MaxConcurrentDeliveries"/> at
/// the same time, and plans the next attempt of a failed one (<see cref="WebhookRetrySchedule"/>) or makes it a dead
/// letter. The outbox is in the database, so pending deliveries survive a restart (at-least-once). It also reloads the
/// webhook catalog every 30 s and removes the old finished deliveries every hour.
/// </summary>
public sealed class WebhookDispatcher : BackgroundService
{
    public static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan LeaseDuration = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan CatalogRefreshInterval = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan CleanupInterval = TimeSpan.FromHours(1);

    private readonly IWebhookStore _store;
    private readonly WebhookCatalog _catalog;
    private readonly WebhookSender _sender;
    private readonly WebhookDispatchSignal _signal;
    private readonly WebhookRetrySchedule _schedule;
    private readonly WebhookOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private DateTime _nextCleanupUtc = DateTime.MinValue;

    public WebhookDispatcher(IWebhookStore store, WebhookCatalog catalog, WebhookSender sender, WebhookDispatchSignal signal,
        WebhookRetrySchedule schedule, IOptions<WebhookOptions> options, TimeProvider time, ILogger<WebhookDispatcher> logger)
    {
        _store = store;
        _catalog = catalog;
        _sender = sender;
        _signal = signal;
        _schedule = schedule;
        _options = options.Value;
        _time = time;
        _logger = logger;
    }

    /// <summary>The lease owner of this node: machine, process and a random part (two hosts in one process differ).</summary>
    public string NodeId { get; } = $"{Environment.MachineName}/{Environment.ProcessId}/{Guid.NewGuid().ToString("N")[..8]}";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_store.IsEnabled)
            return;

        var running = new List<Task>();
        while (!stoppingToken.IsCancellationRequested)
        {
            _signal.Reset();
            var more = false;
            try
            {
                await HousekeepingAsync(stoppingToken);
                running.RemoveAll(t => t.IsCompleted);
                var free = _options.MaxConcurrentDeliveries - running.Count;
                if (free > 0)
                {
                    var now = _time.GetUtcNow().UtcDateTime;
                    var claimed = await _store.ClaimDueAsync(NodeId, now, now + LeaseDuration, free, stoppingToken);
                    foreach (var delivery in claimed)
                        running.Add(DeliverAsync(delivery, stoppingToken));
                    more = claimed.Count == free;
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "The webhook dispatcher failed; it tries again in {Seconds} s.", PollInterval.TotalSeconds);
            }

            if (!more || running.Count >= _options.MaxConcurrentDeliveries)
                await WaitAsync(running, stoppingToken);
        }

        // The deliveries in flight end themselves at the cancellation and give their lease back.
        await Task.WhenAll(running);
    }

    private async Task HousekeepingAsync(CancellationToken ct)
    {
        if (_catalog.Age is not { } age || age >= CatalogRefreshInterval)
            await _catalog.ReloadAsync(ct);

        var now = _time.GetUtcNow().UtcDateTime;
        if (now < _nextCleanupUtc)
            return;
        _nextCleanupUtc = now + CleanupInterval;
        if (_options.DeliveryRetentionDays <= 0)
            return;
        var removed = await _store.DeleteFinishedOlderThanAsync(now - TimeSpan.FromDays(_options.DeliveryRetentionDays), ct);
        if (removed > 0)
            _logger.LogInformation("Removed {Count} webhook deliveries older than {Days} days.", removed, _options.DeliveryRetentionDays);
    }

    /// <summary>Until a delivery was added, one in flight ended, or the poll interval passed (deliveries that became due).</summary>
    private async Task WaitAsync(List<Task> running, CancellationToken stoppingToken)
    {
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var delay = Task.Delay(PollInterval, _time, cancel.Token);
        await Task.WhenAny([_signal.WaitTask, delay, .. running]);
        await cancel.CancelAsync(); // ends the timer
    }

    private async Task DeliverAsync(WebhookDelivery delivery, CancellationToken stoppingToken)
    {
        try
        {
            var webhook = await FindAsync(delivery.WebhookId, stoppingToken);
            var now = _time.GetUtcNow().UtcDateTime;
            if (webhook == null)
            {
                delivery.Status = WebhookDeliveryStatus.DeadLetter;
                delivery.NextAttemptUtc = null;
                delivery.LastError = "The webhook is disabled or removed.";
                await _store.SaveAttemptAsync(delivery, CancellationToken.None);
                return;
            }

            var attempt = delivery.Attempts + 1;
            var response = await _sender.SendAsync(webhook, delivery.DeliveryId, delivery.EventType,
                WebhookPayload.WithAttempt(delivery.Payload, attempt), stoppingToken);
            now = _time.GetUtcNow().UtcDateTime;
            delivery.Attempts = attempt;
            delivery.LastAttemptUtc = now;
            delivery.LastStatusCode = response.StatusCode;
            delivery.ResponseExcerpt = response.Body;
            delivery.LastError = response.IsSuccess ? null : response.Describe();

            if (response.IsSuccess)
            {
                delivery.Status = WebhookDeliveryStatus.Delivered;
                delivery.NextAttemptUtc = null;
                _logger.LogDebug("Delivered {Event} {Delivery} to the webhook {Webhook} (attempt {Attempt}).",
                    delivery.EventType, delivery.DeliveryId, webhook.Name, attempt);
            }
            else if (_schedule.DelayAfter(attempt) is { } delay)
            {
                delivery.Status = WebhookDeliveryStatus.Pending;
                delivery.NextAttemptUtc = now + delay;
                _logger.LogInformation("The webhook {Webhook} failed on {Event} {Delivery} (attempt {Attempt}: {Error}); next attempt in {Delay}. Response: {Response}",
                    webhook.Name, delivery.EventType, delivery.DeliveryId, attempt, response.Describe(), delay, response.Body);
            }
            else
            {
                delivery.Status = WebhookDeliveryStatus.DeadLetter;
                delivery.NextAttemptUtc = null;
                _logger.LogWarning("The webhook {Webhook} failed on {Event} {Delivery} {Attempts} times ({Error}); it is a dead letter now. Response: {Response}",
                    webhook.Name, delivery.EventType, delivery.DeliveryId, attempt, response.Describe(), response.Body);
            }
            await _store.SaveAttemptAsync(delivery, CancellationToken.None);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            await ReleaseAsync(delivery);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "The webhook delivery {Delivery} failed; it is sent again later.", delivery.DeliveryId);
            await ReleaseAsync(delivery);
        }
    }

    /// <summary>The enabled webhook; a reload for one that another node (or the UI of a moment ago) added.</summary>
    private async Task<ActiveWebhook?> FindAsync(int id, CancellationToken ct)
    {
        var snapshot = await _catalog.GetAsync(ct);
        return snapshot.Find(id) ?? (await _catalog.ReloadAsync(ct)).Find(id);
    }

    private async Task ReleaseAsync(WebhookDelivery delivery)
    {
        try
        {
            await _store.ReleaseAsync(delivery.Id, CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "The lease of the webhook delivery {Delivery} could not be given back; it ends by itself.", delivery.DeliveryId);
        }
    }
}
