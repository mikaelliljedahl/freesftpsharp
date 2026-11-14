namespace SshServer.Interfaces.Connections;

/// <summary>
/// A snapshot of one open client connection in the <see cref="IConnectionRegistry"/>. A new snapshot is made for every
/// change, so a snapshot never changes after it is read.
/// </summary>
/// <param name="Id">The id of the connection. It stays the same for the whole connection and is never reused.</param>
/// <param name="Protocol">The protocol, see <see cref="ConnectionProtocols"/>.</param>
/// <param name="RemoteEndPoint">The address and port of the client, for example "127.0.0.1:50123".</param>
/// <param name="ClientVersion">The version string of the client (SSH: "SSH-2.0-OpenSSH_9.6"), or null before the client sent it.</param>
/// <param name="ConnectedAt">When the server accepted the connection.</param>
/// <param name="LastActivity">The last request of the client on its storage, or <paramref name="ConnectedAt"/> or the login before the first one.</param>
/// <param name="Username">The authenticated user, or null before the login.</param>
/// <param name="AuthenticatedAt">When the login succeeded, or null before the login.</param>
/// <param name="AuthMethod">The method of the login (SSH: "password" or "publickey"), or null before the login.</param>
/// <param name="Transfers">The files that are open for reading or writing now.</param>
public sealed record ConnectionInfo(
    Guid Id,
    string Protocol,
    string RemoteEndPoint,
    string? ClientVersion,
    DateTimeOffset ConnectedAt,
    DateTimeOffset LastActivity,
    string? Username,
    DateTimeOffset? AuthenticatedAt,
    string? AuthMethod,
    IReadOnlyList<ActiveTransfer> Transfers)
{
    /// <summary>The node that has the connection (<c>Cluster:NodeId</c>, issue #75); null on a single node.</summary>
    public string? Node { get; init; }
}

/// <summary>A file that a connection reads or writes now.</summary>
/// <param name="Id">The id of the transfer.</param>
/// <param name="VirtualPath">The path of the file for the user ("/" is the user root).</param>
/// <param name="Direction">Upload (the client writes) or download (the client reads).</param>
/// <param name="Bytes">The bytes read or written so far.</param>
/// <param name="StartedAt">When the first byte was read or written.</param>
public sealed record ActiveTransfer(Guid Id, string VirtualPath, TransferDirection Direction, long Bytes, DateTimeOffset StartedAt);

public enum TransferDirection
{
    /// <summary>The client writes to the server.</summary>
    Upload,
    /// <summary>The client reads from the server.</summary>
    Download,
}

/// <summary>The names in <see cref="ConnectionInfo.Protocol"/>.</summary>
public static class ConnectionProtocols
{
    public const string Sftp = "SFTP";
    public const string WebDav = "WebDAV";

    /// <summary>A browser session of the web client (#69); one connection per login.</summary>
    public const string Http = "HTTP";
}

public enum ConnectionEventKind
{
    Connected,
    Authenticated,
    Disconnected,
}

/// <summary>A change of the <see cref="IConnectionRegistry"/>, with the snapshot of the connection after the change.</summary>
public sealed record ConnectionEvent(ConnectionEventKind Kind, ConnectionInfo Connection);

/// <summary>What a protocol gives the registry for a new connection.</summary>
/// <param name="Protocol">The protocol, see <see cref="ConnectionProtocols"/>.</param>
/// <param name="RemoteEndPoint">The address and port of the client.</param>
/// <param name="DisconnectAsync">Closes the connection; the argument is the reason that the client is told. It completes when the connection is closed.</param>
public sealed record ConnectionRegistration(string Protocol, string RemoteEndPoint, Func<string, Task> DisconnectAsync);
