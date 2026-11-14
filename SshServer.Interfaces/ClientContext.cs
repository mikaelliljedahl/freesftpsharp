namespace SshServer.Interfaces;

/// <summary>Who uses a service: the protocol, the address of the client and its connection.</summary>
/// <param name="Protocol">The protocol, for example "SFTP".</param>
/// <param name="RemoteIp">The address of the client; null when there is no network client.</param>
/// <param name="ConnectionId">The <c>ConnectionInfo.Id</c> of the connection in the connection registry; null when the client has no registered connection.</param>
public sealed record ClientContext(string Protocol, string? RemoteIp, Guid? ConnectionId = null);
