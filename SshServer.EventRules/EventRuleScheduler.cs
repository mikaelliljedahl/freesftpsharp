using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.EventRules;

namespace SshServer.EventRules;

/// <summary>
/// Runs the scheduled rules. It wakes at the next occurrence of a schedule (at least every 30 s, to see the rules of
/// another node), and runs each rule whose schedule had an occurrence since the last check: once, also when several
/// occurrences passed (a stopped machine catches up one run, not each one). A node runs an occurrence only when it claims
/// it in the database (<see cref="IEventRuleStore.TryClaimScheduledRunAsync"/>), so with several nodes it runs once. The
/// clock is the <see cref="TimeProvider"/>, so the tests use a fake clock.
/// </summary>
public sealed class EventRuleScheduler : BackgroundService
{
    public static readonly TimeSpan MaxWait = TimeSpan.FromSeconds(30);

    private readonly EventRuleCatalog _catalog;
    private readonly IEventRuleStore _store;
    private readonly EventRuleRunner _runner;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _checkLock = new(1, 1);
    private DateTime _lastCheckUtc;

    public EventRuleScheduler(EventRuleCatalog catalog, IEventRuleStore store, EventRuleRunner runner, TimeProvider time,
        ILogger<EventRuleScheduler> logger)
    {
        _catalog = catalog;
        _store = store;
        _runner = runner;
        _time = time;
        _logger = logger;
        _lastCheckUtc = time.GetUtcNow().UtcDateTime;
    }

    /// <summary>
    /// One check: for each scheduled rule with an occurrence after the last check and at or before now, claims the
    /// latest occurrence and runs the rule. Returns how many rules this node ran.
    /// </summary>
    public async Task<int> RunDueAsync(CancellationToken ct)
    {
        await _checkLock.WaitAsync(ct);
        try
        {
            var now = _time.GetUtcNow().UtcDateTime;
            var from = _lastCheckUtc;
            if (now <= from)
                return 0;
            _lastCheckUtc = now;

            var snapshot = await GetCatalogAsync(ct);
            var ran = 0;
            foreach (var rule in snapshot.ScheduledRules)
            {
                if (rule.Cron is not { } cron || EventRuleSchedule.LastOccurrence(cron, rule.TimeZone, from, now) is not { } occurrence)
                    continue;
                try
                {
                    if (!await _store.TryClaimScheduledRunAsync(rule.Id, occurrence, ct))
                        continue; // another node runs it
                    ran++;
                    await _runner.RunWithoutEventAsync(rule, EventRuleRunner.ScheduleTrigger, ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "The scheduled event rule {Rule} failed.", rule.Name);
                }
            }
            return ran;
        }
        finally
        {
            _checkLock.Release();
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(await NextWaitAsync(stoppingToken), _time, stoppingToken);
                await RunDueAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "The event rule scheduler failed; it tries again in {Seconds} s.", MaxWait.TotalSeconds);
            }
        }
    }

    /// <summary>The time until the next occurrence of a schedule, at most <see cref="MaxWait"/>.</summary>
    private async Task<TimeSpan> NextWaitAsync(CancellationToken ct)
    {
        var snapshot = await GetCatalogAsync(ct);
        var now = _time.GetUtcNow().UtcDateTime;
        var wait = MaxWait;
        foreach (var rule in snapshot.ScheduledRules)
        {
            if (rule.Cron is { } cron && EventRuleSchedule.Next(cron, rule.TimeZone, now) is { } next && next - now < wait)
                wait = next - now;
        }
        return wait < TimeSpan.FromMilliseconds(10) ? TimeSpan.FromMilliseconds(10) : wait;
    }

    private async Task<EventRuleCatalogSnapshot> GetCatalogAsync(CancellationToken ct)
        => _catalog.Age is { } age && age < EventRuleCatalog.RefreshInterval ? await _catalog.GetAsync(ct) : await _catalog.ReloadAsync(ct);
}
