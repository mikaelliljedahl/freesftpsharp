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
