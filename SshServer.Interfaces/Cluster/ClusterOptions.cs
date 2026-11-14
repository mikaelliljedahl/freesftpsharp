namespace SshServer.Interfaces.Cluster;

/// <summary>
/// Several nodes on one settings database (issue #75), the <c>Cluster</c> section. Off by default: one node behaves as
/// before. With <c>Cluster:Enabled</c> each node writes a heartbeat and its connections to the database, reads the
/// connections and the bans of the other nodes, and reloads its cached settings when another node changed them; every
/// <see cref="PollInterval"/>. Needs a SQL settings provider (PostgreSQL or SQL Server for real nodes; SQLite works for
/// several processes on one machine).
/// </summary>
public sealed class ClusterOptions
{
    public const string SectionName = "Cluster";

    /// <summary>True: this node is one of several on the settings database.</summary>
    public bool Enabled { get; init; }

    /// <summary>The name of this node, unique among the nodes (<c>Cluster:NodeId</c>; default: host name and a random suffix).</summary>
    public string NodeId { get; init; } = DefaultNodeId();

    /// <summary>How often a node writes its heartbeat and reads the shared state (<c>Cluster:PollIntervalSeconds</c>, 1-60, default 5).</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>A node without a heartbeat for this long is gone: its connections are not shown, its rows are removed.</summary>
    public TimeSpan NodeTimeout => TimeSpan.FromTicks(Math.Max(PollInterval.Ticks * 4, TimeSpan.FromSeconds(15).Ticks));

    public static string DefaultNodeId() => $"{Environment.MachineName}-{Guid.NewGuid().ToString("N")[..6]}";
}

/// <summary>A server node in the settings database, with its last heartbeat.</summary>
public sealed record NodeInfo(string NodeId, string Hostname, string Version, DateTimeOffset StartedAt, DateTimeOffset LastSeen);

/// <summary>A request of another node to close a connection of the node <paramref name="NodeId"/>.</summary>
public sealed record DisconnectRequest(long Id, string NodeId, Guid ConnectionId, string Reason);

/// <summary>
/// The shared state of the nodes in the settings database: the nodes with their heartbeat, the open connections of each
/// node, and the requests to close a connection on its node.
/// </summary>
public interface IClusterStore
{
    /// <summary>Writes the heartbeat of <paramref name="node"/> and replaces its stored connections with <paramref name="connections"/>.</summary>
    Task HeartbeatAsync(NodeInfo node, IReadOnlyList<Connections.ConnectionInfo> connections, CancellationToken ct);

    Task<IReadOnlyList<NodeInfo>> ListNodesAsync(CancellationToken ct);

    /// <summary>The stored connections of the nodes seen since <paramref name="aliveSince"/>, each with its <see cref="Connections.ConnectionInfo.Node"/>.</summary>
    Task<IReadOnlyList<Connections.ConnectionInfo>> ListConnectionsAsync(DateTimeOffset aliveSince, CancellationToken ct);

    Task RequestDisconnectAsync(string nodeId, Guid connectionId, string reason, DateTimeOffset now, CancellationToken ct);

    /// <summary>Returns and removes the disconnect requests for <paramref name="nodeId"/>.</summary>
    Task<IReadOnlyList<DisconnectRequest>> TakeDisconnectRequestsAsync(string nodeId, CancellationToken ct);

    /// <summary>Removes a node with its connections and requests (at its stop).</summary>
    Task RemoveNodeAsync(string nodeId, CancellationToken ct);

    /// <summary>Removes the nodes without a heartbeat since <paramref name="seenBefore"/>, with their connections and requests.</summary>
    Task<int> RemoveStaleNodesAsync(DateTimeOffset seenBefore, CancellationToken ct);
}

/// <summary>
/// A counter in the settings database that grows with every change of the settings (users, groups, folders, server
/// settings, webhooks, rules, administrators), so that a node sees that another node changed something.
/// </summary>
public interface ISettingsVersionStore
{
    Task<long> GetAsync(CancellationToken ct);

    Task BumpAsync(CancellationToken ct);
}

/// <summary>
/// Raised when the settings were changed, also by another node (<see cref="ISettingsVersionStore"/>, polled every
/// <see cref="ClusterOptions.PollInterval"/>). The in-memory caches (webhooks, event rules) reload on it. A single node
/// never raises it: its caches reload after its own changes.
/// </summary>
public interface ISettingsChangeNotifier
{
    event Action? Changed;
}

/// <summary>The <see cref="ISettingsChangeNotifier"/> of a single node: never raised.</summary>
public sealed class NoSettingsChanges : ISettingsChangeNotifier
{
    public event Action? Changed
    {
        add { }
        remove { }
    }
}
