#nullable enable
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;

namespace SshServerModule.Connections
{
    /// <summary>
    /// Closes the open sessions of a user that an administrator disables or removes (issue #61), in every protocol through
    /// the <see cref="IConnectionRegistry"/>. It reads the provider events of the settings store, so the admin UI, the
    /// command line and later the REST API need no code of their own. A user that expires keeps its open sessions.
    /// </summary>
    public sealed class DisabledUserDisconnector : IEventSink
    {
        private readonly IConnectionRegistry _connections;
        private readonly ILogger _logger;

        public DisabledUserDisconnector(IConnectionRegistry connections, ILogger<DisabledUserDisconnector>? logger = null)
        {
            _connections = connections ?? throw new ArgumentNullException(nameof(connections));
            _logger = (ILogger?)logger ?? NullLogger.Instance;
        }

        public async ValueTask HandleAsync(IEvent @event, CancellationToken ct)
        {
            if (@event is not ProviderEvent { ObjectType: ProviderObjectType.User } change)
                return;
            string reason;
            if (change.Action == ProviderAction.Delete)
                reason = "The user was removed.";
            else if (change.Action == ProviderAction.Update && change.ChangedFields.Contains(nameof(UserSnapshot.Status))
                     && change.Object is UserSnapshot { Status: "Disabled" })
                reason = "The user was disabled.";
            else
                return;

            foreach (var connection in _connections.GetAll()
                         .Where(c => string.Equals(c.Username, change.ObjectName, StringComparison.OrdinalIgnoreCase)))
            {
                _logger.LogInformation("Closing connection {ConnectionId} of {Username}: {Reason}", connection.Id, connection.Username, reason);
                await _connections.DisconnectAsync(connection.Id, reason);
            }
        }
    }
}
