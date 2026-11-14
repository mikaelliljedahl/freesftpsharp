using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Audit;
using SshServer.Interfaces.Events;

namespace SshServer.Settings.Sql.Audit;

/// <summary>
/// Removes the audit entries older than <see cref="AuditOptions.RetentionDays"/>: once at the start, then once a day.
/// Each run publishes a <see cref="SystemEventType.ScheduledJobRan"/> event.
/// </summary>
public sealed class AuditRetentionService : BackgroundService
{
    public const string JobName = "AuditRetention";
    public static readonly TimeSpan Interval = TimeSpan.FromDays(1);

    private readonly IAuditLog _log;
    private readonly AuditOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly IEventBus? _events;

    public AuditRetentionService(IAuditLog log, IOptions<AuditOptions> options, TimeProvider time, ILogger<AuditRetentionService> logger,
        IEventBus? events = null)
    {
        _log = log;
        _options = options.Value;
        _time = time;
        _logger = logger;
        _events = events;
    }

    /// <summary>One run: removes the old entries; returns how many.</summary>
    public async Task<int> RunOnceAsync(CancellationToken ct)
    {
        if (!_log.IsEnabled || _options.RetentionDays <= 0)
            return 0;

        var cutoff = _time.GetUtcNow().UtcDateTime - TimeSpan.FromDays(_options.RetentionDays);
        var removed = await _log.DeleteOlderThanAsync(cutoff, ct);
        _logger.LogInformation("Removed {Count} audit entries older than {Days} days.", removed, _options.RetentionDays);
        if (_events != null)
            await _events.PublishAsync(new SystemEvent(SystemEventType.ScheduledJobRan)
            {
                Timestamp = _time.GetUtcNow(),
                Source = JobName,
                Message = $"Removed {removed} audit entries older than {_options.RetentionDays} days.",
            }, ct);
        return removed;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            // Start the timer before the run, so the next run is one interval after the start of this run.
            // The timer then exists before the run gives a result, and a test with a fake TimeProvider
            // that advances the time after the result cannot miss the timer.
            var next = Task.Delay(Interval, _time, stoppingToken);
            try
            {
                await RunOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "The audit retention job failed; it runs again in {Interval}.", Interval);
            }

            try
            {
                await next;
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }
}
