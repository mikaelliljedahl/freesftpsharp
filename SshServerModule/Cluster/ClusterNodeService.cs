#nullable enable
using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Cluster;
using SshServer.Interfaces.Connections;

namespace SshServerModule.Cluster
{
    /// <summary>
    /// The work of a node of several (issue #75, <c>Cluster:Enabled</c>), every <see cref="ClusterOptions.PollInterval"/>:
    /// writes the heartbeat and the connections of this node, removes the nodes without a heartbeat, reads the connections
    /// of the other nodes, closes the connections that another node asked for, takes the shared bans, and tells the caches
    /// when the settings version changed. At the stop it removes its node. A failure is logged and tried again at the next
    /// poll; the protocols never wait for it.
    /// </summary>
    public sealed class ClusterNodeService : BackgroundService
    {
        private readonly ClusterOptions _options;
        private readonly IClusterStore _store;
        private readonly ISettingsVersionStore _versions;
        private readonly IConnectionRegistry _registry;
        private readonly ClusterConnections _connections;
        private readonly RemoteConnections _remote;
        private readonly ClusterSettingsChangeNotifier _notifier;
        private readonly LoginBanTracker _bans;
        private readonly ISettingsRepository _settings;
        private readonly TimeProvider _time;
        private readonly ILogger _logger;
        private readonly DateTimeOffset _startedAt;
        private readonly string _version;

        public ClusterNodeService(ClusterOptions options, IClusterStore store, ISettingsVersionStore versions, IConnectionRegistry registry,
            ClusterConnections connections, RemoteConnections remote, ClusterSettingsChangeNotifier notifier, LoginBanTracker bans, ISettingsRepository settings,
            TimeProvider time, ILogger<ClusterNodeService> logger)
        {
            _options = options;
            _store = store;
            _versions = versions;
            _registry = registry;
            _connections = connections;
            _remote = remote;
            _notifier = notifier;
            _bans = bans;
            _settings = settings; // resolved first: the repository creates and migrates the database
            _time = time;
            _logger = logger;
            _startedAt = time.GetUtcNow();
            _version = typeof(ClusterNodeService).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "?";
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Cluster node {NodeId}: shared state every {Seconds} s.", _options.NodeId, _options.PollInterval.TotalSeconds);
            using var timer = new PeriodicTimer(_options.PollInterval, _time);
            do
            {
                await PollAsync(stoppingToken);
            }
            while (await WaitAsync(timer, stoppingToken));
        }

        private static async Task<bool> WaitAsync(PeriodicTimer timer, CancellationToken ct)
        {
            try
            {
                return await timer.WaitForNextTickAsync(ct);
            }
            catch (OperationCanceledException)
            {
                return false;
            }
        }

        /// <summary>One poll (also for the tests).</summary>
        internal async Task PollAsync(CancellationToken ct)
        {
            try
            {
                var now = _time.GetUtcNow();
                await _store.HeartbeatAsync(new NodeInfo(_options.NodeId, Environment.MachineName, _version, _startedAt, now), _connections.Local(), ct);
                await _store.RemoveStaleNodesAsync(now - _options.NodeTimeout, ct);
                _remote.Set(await _store.ListConnectionsAsync(now - _options.NodeTimeout, ct));

                foreach (var request in await _store.TakeDisconnectRequestsAsync(_options.NodeId, ct))
                {
                    _logger.LogInformation("Closing connection {ConnectionId} at the request of another node: {Reason}", request.ConnectionId, request.Reason);
                    await _registry.DisconnectAsync(request.ConnectionId, request.Reason);
                }

                await _bans.SyncAsync(ct);
                _notifier.Observe(await _versions.GetAsync(ct));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Cluster node {NodeId}: the shared state could not be read or written; trying again.", _options.NodeId);
            }
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            await base.StopAsync(cancellationToken);
            try
            {
                await _store.RemoveNodeAsync(_options.NodeId, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Cluster node {NodeId}: could not remove the node; the other nodes drop it after {Seconds} s.",
                    _options.NodeId, _options.NodeTimeout.TotalSeconds);
            }
        }
    }
}
