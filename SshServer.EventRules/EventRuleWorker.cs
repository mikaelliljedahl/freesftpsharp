using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SshServer.EventRules;

/// <summary>
/// Runs the queued rule runs (<see cref="EventRuleQueue"/>) in the background: at most
/// <see cref="EventRuleOptions.MaxConcurrentRuns"/> runs of events at the same time, and the runs that an operation
/// waits for (<c>Pre*</c> events) at once, each on its own.
/// </summary>
public sealed class EventRuleWorker : BackgroundService
{
    private readonly EventRuleQueue _queue;
    private readonly EventRuleRunner _runner;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _slots;

    public EventRuleWorker(EventRuleQueue queue, EventRuleRunner runner, IOptions<EventRuleOptions> options, ILogger<EventRuleWorker> logger)
    {
        _queue = queue;
        _runner = runner;
        _logger = logger;
        _slots = new SemaphoreSlim(options.Value.MaxConcurrentRuns, options.Value.MaxConcurrentRuns);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var running = new List<Task>();
        try
        {
            await Task.WhenAll(ReadBackgroundAsync(running, stoppingToken), ReadWaitingAsync(running, stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Stopped.
        }

        Task[] pending;
        lock (running)
            pending = running.ToArray();
        await Task.WhenAll(pending);
        while (_queue.Waiting.TryRead(out var job))
            job.Completion?.TrySetCanceled(CancellationToken.None);
    }

    private async Task ReadBackgroundAsync(List<Task> running, CancellationToken stoppingToken)
    {
        await foreach (var job in _queue.Background.ReadAllAsync(stoppingToken))
        {
            await _slots.WaitAsync(stoppingToken);
            Track(running, RunAsync(job, release: true, stoppingToken));
        }
    }

    private async Task ReadWaitingAsync(List<Task> running, CancellationToken stoppingToken)
    {
        await foreach (var job in _queue.Waiting.ReadAllAsync(stoppingToken))
            Track(running, RunAsync(job, release: false, stoppingToken));
    }

    private static void Track(List<Task> running, Task task)
    {
        lock (running)
        {
            running.RemoveAll(t => t.IsCompleted);
            running.Add(task);
        }
    }

    private async Task RunAsync(EventRuleJob job, bool release, CancellationToken stoppingToken)
    {
        await Task.Yield(); // the reader goes on while this run works
        try
        {
            var run = await _runner.RunForEventAsync(job.Rule, job.Event, stoppingToken);
            job.Completion?.TrySetResult(run);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            job.Completion?.TrySetCanceled(stoppingToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "The event rule {Rule} failed on {Event}.", job.Rule.Name, job.Event.TypeName);
            job.Completion?.TrySetException(ex);
        }
        finally
        {
            if (release)
                _slots.Release();
        }
    }
}
