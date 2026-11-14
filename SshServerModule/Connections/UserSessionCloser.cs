#nullable enable
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using FxSsh.SshServerModule.Security;

namespace SshServerModule.Connections
{
    /// <summary>
    /// The one place that closes the open sessions of a user whose account ended (issues #61 and #132), in every protocol
    /// through the <see cref="IConnectionRegistry"/>; no protocol has code of its own. As an <see cref="IEventSink"/> it
    /// reads the provider events of the settings store, so the admin UI, the command line and the REST API need no code:
    /// a user that is disabled or removed loses its sessions. <see cref="UserLifecycleService"/> calls
    /// <see cref="CloseSessionsAsync"/> for a user that expired. Each close is logged and published as a
    /// <see cref="SystemEventType.SessionsClosed"/> event, which is in the audit log with the reason. With several nodes
    /// (issue #75) it closes the sessions on the other nodes too, through <see cref="IClusterConnections"/>.
    /// </summary>
    public sealed class UserSessionCloser : IEventSink
    {
        public const string ExpiredReason = "The account expired.";
        public const string DisabledReason = "The account was disabled.";
        public const string RemovedReason = "The account was removed.";

        private readonly IClusterConnections _connections;
        private readonly Func<IEventBus?> _events;
        private readonly TimeProvider _time;
        private readonly ILogger _logger;

        /// <param name="events">
        /// The event bus, asked when it is needed: the bus holds this sink, so it cannot be a constructor dependency.
        /// </param>
        public UserSessionCloser(IConnectionRegistry connections, Func<IEventBus?>? events = null, TimeProvider? time = null,
            ILogger<UserSessionCloser>? logger = null, IClusterConnections? cluster = null)
        {
            ArgumentNullException.ThrowIfNull(connections);
            _connections = cluster ?? new LocalClusterConnections(connections);
            _events = events ?? (() => null);
            _time = time ?? TimeProvider.System;
            _logger = (ILogger?)logger ?? NullLogger.Instance;
        }

        public async ValueTask HandleAsync(IEvent @event, CancellationToken ct)
        {
            if (@event is not ProviderEvent { ObjectType: ProviderObjectType.User } change)
                return;
            string reason;
            if (change.Action == ProviderAction.Delete)
                reason = RemovedReason;
            else if (change.Action == ProviderAction.Update && change.ChangedFields.Contains(nameof(UserSnapshot.Status))
                     && change.Object is UserSnapshot { Status: "Disabled" })
                reason = DisabledReason;
            else
                return;

            await CloseSessionsAsync(change.ObjectName, reason, ct);
        }

        /// <summary>Closes every connection of <paramref name="username"/> (without case) with <paramref name="reason"/>. Returns how many it closed.</summary>
        public async Task<int> CloseSessionsAsync(string username, string reason, CancellationToken ct = default)
        {
            var closed = 0;
            foreach (var connection in _connections.GetAll()
                         .Where(c => string.Equals(c.Username, username, StringComparison.OrdinalIgnoreCase)))
            {
                _logger.LogInformation("Closing connection {ConnectionId} of {Username}: {Reason}", connection.Id, LogText.Clean(connection.Username), reason);
                if (!await _connections.DisconnectAsync(connection.Id, reason))
                    continue;
                closed++;
                if (_events() is { } bus)
                {
                    await bus.PublishAsync(new SystemEvent(SystemEventType.SessionsClosed)
                    {
                        Timestamp = _time.GetUtcNow(),
                        Source = connection.Protocol,
                        Message = $"{connection.Username} from {connection.RemoteEndPoint}: {reason}",
                    }, ct);
                }
            }
            return closed;
        }
    }
}
