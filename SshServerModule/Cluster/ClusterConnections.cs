#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces.Cluster;
using SshServer.Interfaces.Connections;

namespace SshServerModule.Cluster
{
    /// <summary>
    /// The <see cref="IClusterConnections"/> of a node of several (issue #75): the connections of this node from the
    /// registry, and the connections of the other nodes as the <see cref="ClusterNodeService"/> read them at its last poll
    /// (no database read for a page or an API call). A connection of another node is closed through a
    /// <see cref="DisconnectRequest"/> that its node reads at its next poll.
    /// </summary>
    public sealed class ClusterConnections : IClusterConnections
    {
        private readonly IConnectionRegistry _registry;
        private readonly IClusterStore _store;
        private readonly ClusterOptions _options;
        private readonly TimeProvider _time;
        private volatile IReadOnlyList<ConnectionInfo> _remote = [];

        public ClusterConnections(IConnectionRegistry registry, IClusterStore store, ClusterOptions options, TimeProvider time)
        {
            _registry = registry;
            _store = store;
            _options = options;
            _time = time;
        }

        /// <summary>The connections of this node, each with the id of this node.</summary>
        public IReadOnlyList<ConnectionInfo> Local() => _registry.GetAll().Select(c => c with { Node = _options.NodeId }).ToList();

        /// <summary>Called by the node service with the stored connections of the live nodes.</summary>
        internal void SetRemote(IEnumerable<ConnectionInfo> stored)
            => _remote = stored.Where(c => c.Node != _options.NodeId).ToList();

        public IReadOnlyList<ConnectionInfo> GetAll() => Local().Concat(_remote).OrderBy(c => c.ConnectedAt).ToList();

        public ConnectionInfo? Get(Guid id)
            => _registry.Get(id) is { } local ? local with { Node = _options.NodeId } : _remote.FirstOrDefault(c => c.Id == id);

        public async Task<bool> DisconnectAsync(Guid id, string reason)
        {
            if (_registry.Get(id) != null)
                return await _registry.DisconnectAsync(id, reason);
            var remote = _remote.FirstOrDefault(c => c.Id == id);
            if (remote?.Node == null)
                return false;
            await _store.RequestDisconnectAsync(remote.Node, id, reason, _time.GetUtcNow(), CancellationToken.None);
            _remote = _remote.Where(c => c.Id != id).ToList();
            return true;
        }
    }

    /// <summary>
    /// The <see cref="ISettingsChangeNotifier"/> of a node of several: raised when the stored settings version changed
    /// since the last poll of the <see cref="ClusterNodeService"/>.
    /// </summary>
    public sealed class ClusterSettingsChangeNotifier : ISettingsChangeNotifier
    {
        private long? _version;

        public event Action? Changed;

        /// <summary>Takes the stored version; raises <see cref="Changed"/> when it is not the one of the last call.</summary>
        internal void Observe(long version)
        {
            var previous = _version;
            _version = version;
            if (previous != null && previous != version)
                Changed?.Invoke();
        }
    }
}
