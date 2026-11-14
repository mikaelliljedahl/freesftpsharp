#nullable enable
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Interfaces.Connections;

namespace SshServerModule.Connections
{
    /// <summary>The in-memory <see cref="IConnectionRegistry"/> of this process (a singleton, see <see cref="ConnectionServiceCollectionExtensions"/>).</summary>
    public sealed class ConnectionRegistry : IConnectionRegistry
    {
        private readonly ConcurrentDictionary<Guid, Entry> _connections = new();
        private readonly TimeProvider _time;
        private readonly ILogger _logger;
        private long _sequence;

        public ConnectionRegistry(TimeProvider time, ILogger<ConnectionRegistry>? logger = null)
        {
            _time = time ?? throw new ArgumentNullException(nameof(time));
            _logger = (ILogger?)logger ?? NullLogger.Instance;
        }

        public event Action<ConnectionEvent>? Changed;

        public ConnectionInfo Register(ConnectionRegistration registration)
        {
            ArgumentNullException.ThrowIfNull(registration);
            ArgumentNullException.ThrowIfNull(registration.DisconnectAsync);

            var now = _time.GetUtcNow();
            var info = new ConnectionInfo(Guid.NewGuid(), registration.Protocol, registration.RemoteEndPoint, null, now, now,
                null, null, null, Array.Empty<ActiveTransfer>());
            var entry = new Entry(info, registration.DisconnectAsync, Interlocked.Increment(ref _sequence));
            _connections[info.Id] = entry;
            Raise(ConnectionEventKind.Connected, entry.Snapshot());
            return info;
        }

        public void SetClientVersion(Guid id, string clientVersion)
            => Update(id, info => info with { ClientVersion = clientVersion });

        public void SetAuthenticated(Guid id, string username, string authMethod)
        {
            var now = _time.GetUtcNow();
            var snapshot = Update(id, info => info with
            {
                Username = username,
                AuthMethod = authMethod,
                AuthenticatedAt = now,
                LastActivity = now,
            });
            if (snapshot != null)
                Raise(ConnectionEventKind.Authenticated, snapshot);
        }

        public void RecordActivity(Guid id)
        {
            var now = _time.GetUtcNow();
            Update(id, info => info with { LastActivity = now });
        }

        public ITransferProgress BeginTransfer(Guid id, string virtualPath, TransferDirection direction)
        {
            if (!_connections.TryGetValue(id, out var entry))
                return NoTransfer.Instance;

            var transfer = new Transfer(Guid.NewGuid(), virtualPath, direction, _time.GetUtcNow());
            lock (entry)
            {
                entry.Transfers[transfer.Id] = transfer;
                entry.Info = entry.Info with { LastActivity = transfer.StartedAt };
            }
            return new TransferProgress(this, entry, transfer);
        }

        public bool Unregister(Guid id)
        {
            if (!_connections.TryRemove(id, out var entry))
                return false;
            Raise(ConnectionEventKind.Disconnected, entry.Snapshot());
            return true;
        }

        public IReadOnlyList<ConnectionInfo> GetAll()
            => _connections.Values.OrderBy(e => e.Sequence).Select(e => e.Snapshot()).ToList();

        public ConnectionInfo? Get(Guid id)
            => _connections.TryGetValue(id, out var entry) ? entry.Snapshot() : null;

        public async Task<bool> DisconnectAsync(Guid id, string reason)
        {
            if (!_connections.TryGetValue(id, out var entry))
                return false;

            var info = entry.Snapshot();
            _logger.LogInformation("Disconnecting {Protocol} connection {ConnectionId} of {Username} from {RemoteEndPoint}: {Reason}",
                info.Protocol, id, info.Username, info.RemoteEndPoint, reason);
            await entry.DisconnectAsync(reason);
            // The protocol normally unregisters from its own close event; this covers a protocol that does not.
            Unregister(id);
            return true;
        }

        private ConnectionInfo? Update(Guid id, Func<ConnectionInfo, ConnectionInfo> change)
        {
            if (!_connections.TryGetValue(id, out var entry))
                return null;
            lock (entry)
            {
                entry.Info = change(entry.Info);
                return entry.SnapshotLocked();
            }
        }

        private void Raise(ConnectionEventKind kind, ConnectionInfo snapshot)
        {
            var handlers = Changed;
            if (handlers == null)
                return;

            var connectionEvent = new ConnectionEvent(kind, snapshot);
            foreach (var handler in handlers.GetInvocationList().Cast<Action<ConnectionEvent>>())
            {
                try
                {
                    handler(connectionEvent);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "A handler of the connection event {Kind} of {ConnectionId} failed.", kind, snapshot.Id);
                }
            }
        }

        private sealed class Entry
        {
            public Entry(ConnectionInfo info, Func<string, Task> disconnectAsync, long sequence)
            {
                Info = info;
                DisconnectAsync = disconnectAsync;
                Sequence = sequence;
            }

            /// <summary>The connection without its transfers. Lock the entry to change it.</summary>
            public ConnectionInfo Info { get; set; }
            public Dictionary<Guid, Transfer> Transfers { get; } = new();
            public Func<string, Task> DisconnectAsync { get; }
            public long Sequence { get; }

            public ConnectionInfo Snapshot()
            {
                lock (this)
                    return SnapshotLocked();
            }

            public ConnectionInfo SnapshotLocked()
                => Info with
                {
                    Transfers = Transfers.Values
                        .OrderBy(t => t.StartedAt)
                        .Select(t => new ActiveTransfer(t.Id, t.VirtualPath, t.Direction, t.Bytes, t.StartedAt))
                        .ToArray(),
                };
        }

        /// <summary>The state of a transfer. Lock its <see cref="Entry"/> to change it.</summary>
        private sealed class Transfer
        {
            public Transfer(Guid id, string virtualPath, TransferDirection direction, DateTimeOffset startedAt)
            {
                Id = id;
                VirtualPath = virtualPath;
                Direction = direction;
                StartedAt = startedAt;
            }

            public Guid Id { get; }
            public string VirtualPath { get; }
            public TransferDirection Direction { get; }
            public DateTimeOffset StartedAt { get; }
            public long Bytes { get; set; }
        }

        private sealed class TransferProgress : ITransferProgress
        {
            private readonly ConnectionRegistry _registry;
            private readonly Entry _entry;
            private readonly Transfer _transfer;

            public TransferProgress(ConnectionRegistry registry, Entry entry, Transfer transfer)
            {
                _registry = registry;
                _entry = entry;
                _transfer = transfer;
            }

            public void AddBytes(long count)
            {
                var now = _registry._time.GetUtcNow();
                lock (_entry)
                {
                    _transfer.Bytes += count;
                    _entry.Info = _entry.Info with { LastActivity = now };
                }
            }

            public void Dispose()
            {
                lock (_entry)
                    _entry.Transfers.Remove(_transfer.Id);
            }
        }

        private sealed class NoTransfer : ITransferProgress
        {
            public static readonly NoTransfer Instance = new();

            public void AddBytes(long count)
            {
            }

            public void Dispose()
            {
            }
        }
    }
}
