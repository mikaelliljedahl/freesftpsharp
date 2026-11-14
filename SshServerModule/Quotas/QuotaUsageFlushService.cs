#nullable enable
using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace SshServerModule.Quotas
{
    /// <summary>Writes the changed quota counters of the <see cref="QuotaUsageTracker"/> to the store every <see cref="QuotaOptions.FlushInterval"/>, and when the host stops.</summary>
    public sealed class QuotaUsageFlushService : BackgroundService
    {
        private readonly QuotaUsageTracker _tracker;
        private readonly TimeSpan _interval;
        private readonly TimeProvider _time;
        private readonly ILogger _logger;

        public QuotaUsageFlushService(QuotaUsageTracker tracker, IOptions<QuotaOptions>? options = null, TimeProvider? time = null, ILogger<QuotaUsageFlushService>? logger = null)
        {
            _tracker = tracker;
            _interval = options?.Value.FlushInterval ?? new QuotaOptions().FlushInterval;
            _time = time ?? TimeProvider.System;
            _logger = (ILogger?)logger ?? NullLogger.Instance;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_interval, _time, stoppingToken);
                    await _tracker.FlushAsync(stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Could not save the quota counters; the next try is in {Interval}.", _interval);
                }
            }
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            await base.StopAsync(cancellationToken);
            await _tracker.FlushAsync(cancellationToken); // the last changes of the sessions
        }
    }
}
