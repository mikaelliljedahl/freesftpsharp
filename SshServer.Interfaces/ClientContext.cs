namespace SshServer.Interfaces;

/// <summary>Who uses a service: the protocol, the address of the client and its connection.</summary>
/// <param name="Protocol">The protocol, for example "SFTP".</param>
/// <param name="RemoteIp">The address of the client; null when there is no network client.</param>
/// <param name="ConnectionId">The <c>ConnectionInfo.Id</c> of the connection in the connection registry; null when the client has no registered connection.</param>
public sealed record ClientContext(string Protocol, string? RemoteIp, Guid? ConnectionId = null)
{
    /// <summary>
    /// True for an operation of the server itself on the files of a user, for example an action of an event rule (#68):
    /// the per-path permissions and path filters of the user are not applied (the user root still is). A protocol
    /// never sets it.
    /// </summary>
    public bool SkipPermissions { get; init; }
}
