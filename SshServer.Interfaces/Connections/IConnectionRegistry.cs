namespace SshServer.Interfaces.Connections;

/// <summary>
/// The open client connections of this server process (no persistence; each node has its own). Every protocol
/// registers its connections here, so the admin UI, the API, session limits and metrics see all of them.
/// All members are thread safe. An unknown or removed id is ignored by the update methods.
/// </summary>
public interface IConnectionRegistry
{
    /// <summary>
    /// Raised after a connection was added, authenticated or removed. It is raised on the thread of the change, outside
    /// the registry lock; an exception of a handler is logged and does not reach the protocol.
    /// </summary>
    event Action<ConnectionEvent>? Changed;

    /// <summary>Adds a new connection and returns its first snapshot (with the new <see cref="ConnectionInfo.Id"/>).</summary>
    ConnectionInfo Register(ConnectionRegistration registration);

    /// <summary>Sets the version string that the client sent.</summary>
    void SetClientVersion(Guid id, string clientVersion);

    /// <summary>Records the successful login of <paramref name="username"/> with <paramref name="authMethod"/>.</summary>
    void SetAuthenticated(Guid id, string username, string authMethod);

    /// <summary>
    /// Records the login like <see cref="SetAuthenticated"/> only when <paramref name="username"/> (without case) has
    /// fewer than <paramref name="maxSessions"/> other authenticated connections; the count and the change are one step,
    /// so two logins at the same time cannot both take the last session (issue #61). 0: no limit. False: the connection
    /// stays unauthenticated (also for an unknown id).
    /// </summary>
    bool TrySetAuthenticated(Guid id, string username, string authMethod, int maxSessions);

    /// <summary>The number of authenticated connections of <paramref name="username"/> (without case), except <paramref name="except"/>.</summary>
    int CountSessions(string username, Guid except);

    /// <summary>Sets <see cref="ConnectionInfo.LastActivity"/> to now.</summary>
    void RecordActivity(Guid id);

    /// <summary>
    /// Starts a transfer of the connection. The caller counts the bytes with <see cref="ITransferProgress.AddBytes"/>
    /// and disposes the progress when the file is closed. For an unknown id the progress does nothing.
    /// </summary>
    ITransferProgress BeginTransfer(Guid id, string virtualPath, TransferDirection direction);

    /// <summary>Removes a connection after it was closed. False when it was not registered (any more).</summary>
    bool Unregister(Guid id);

    /// <summary>The connections now, oldest first.</summary>
    IReadOnlyList<ConnectionInfo> GetAll();

    /// <summary>The connection with <paramref name="id"/>, or null.</summary>
    ConnectionInfo? Get(Guid id);

    /// <summary>
    /// Closes a connection and removes it. <paramref name="reason"/> is sent to the client where the protocol can.
    /// False when the connection is not registered.
    /// </summary>
    Task<bool> DisconnectAsync(Guid id, string reason);
}

/// <summary>The byte count of one transfer in the <see cref="IConnectionRegistry"/>. Dispose it to end the transfer.</summary>
public interface ITransferProgress : IDisposable
{
    /// <summary>Adds <paramref name="count"/> bytes to the transfer and records activity of the connection.</summary>
    void AddBytes(long count);
}

/// <summary>
/// The open connections of every node (issue #75): the <see cref="IConnectionRegistry"/> of this node and, with
/// <c>Cluster:Enabled</c>, the connections that the other nodes stored in the settings database. The admin UI and the
/// REST API list and close connections through it. On a single node it is the registry.
/// </summary>
public interface IClusterConnections
{
    /// <summary>The connections of all nodes now, oldest first. It reads no database (the other nodes are cached).</summary>
    IReadOnlyList<ConnectionInfo> GetAll();

    ConnectionInfo? Get(Guid id);

    /// <summary>
    /// Closes a connection: at once on this node; on another node through a request that the node reads within its poll
    /// interval. False when the connection is not known.
    /// </summary>
    Task<bool> DisconnectAsync(Guid id, string reason);
}

/// <summary>The <see cref="IClusterConnections"/> of a single node: the registry.</summary>
public sealed class LocalClusterConnections : IClusterConnections
{
    private readonly IConnectionRegistry _registry;

    public LocalClusterConnections(IConnectionRegistry registry)
    {
        _registry = registry;
    }

    public IReadOnlyList<ConnectionInfo> GetAll() => _registry.GetAll();

    public ConnectionInfo? Get(Guid id) => _registry.Get(id);

    public Task<bool> DisconnectAsync(Guid id, string reason) => _registry.DisconnectAsync(id, reason);
}
