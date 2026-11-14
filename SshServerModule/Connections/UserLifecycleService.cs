#nullable enable
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Users;

namespace SshServerModule.Connections
{
    /// <summary>
    /// Closes the open sessions of a user that expires (issue #132). The expiry is a point in time, not a change of the
    /// store, so nothing publishes an event for it: every <see cref="Interval"/> this checks the users of the open
    /// connections against <see cref="UserLoginRules"/> and lets the <see cref="UserSessionCloser"/> close them. It also
    /// closes the sessions of a user that is disabled, as a safety net for a change that bypassed the event bus.
    /// </summary>
    public sealed class UserLifecycleService : BackgroundService
    {
        /// <summary>The default time between two checks.</summary>
        public static readonly TimeSpan DefaultInterval = TimeSpan.FromSeconds(5);

        private readonly IConnectionRegistry _connections;
        private readonly ISettingsRepository? _repository;
        private readonly UserSessionCloser _closer;
        private readonly TimeProvider _time;
        private readonly ILogger _logger;

        public UserLifecycleService(IConnectionRegistry connections, UserSessionCloser closer, ISettingsRepository? repository = null,
            TimeProvider? time = null, ILogger<UserLifecycleService>? logger = null)
        {
            _connections = connections ?? throw new ArgumentNullException(nameof(connections));
            _closer = closer ?? throw new ArgumentNullException(nameof(closer));
            _repository = repository;
            _time = time ?? TimeProvider.System;
            _logger = (ILogger?)logger ?? NullLogger.Instance;
        }

        /// <summary>The time between two checks.</summary>
        public TimeSpan Interval { get; init; } = DefaultInterval;

        /// <summary>Checks the users of the open connections once. Returns how many connections it closed.</summary>
        public async Task<int> CheckAsync(CancellationToken ct = default)
        {
            if (_repository is null)
                return 0;
            var now = _time.GetUtcNow().UtcDateTime;
            var closed = 0;
            var users = _connections.GetAll().Select(c => c.Username).Where(n => !string.IsNullOrEmpty(n))
                .Distinct(StringComparer.OrdinalIgnoreCase);
            foreach (var name in users)
            {
                // A user that is not stored (removed, or from an external provider) is not this service's business.
                if (_repository.GetUser(name!) is not { } user)
                    continue;
                if (user.Status == UserStatus.Disabled)
                    closed += await _closer.CloseSessionsAsync(user.Username, UserSessionCloser.DisabledReason, ct);
                else if (UserLoginRules.IsExpired(user, now))
                    closed += await _closer.CloseSessionsAsync(user.Username, UserSessionCloser.ExpiredReason, ct);
            }
            return closed;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(Interval, _time, stoppingToken);
                    await CheckAsync(stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Could not check the users of the open sessions; the next try is in {Interval}.", Interval);
                }
            }
        }
    }
}
