namespace SshServer.Interfaces;

/// <summary>Who uses a service: the protocol, the address of the client and its session.</summary>
/// <param name="Protocol">The protocol, for example "SFTP".</param>
/// <param name="RemoteIp">The address of the client; null when there is no network client.</param>
/// <param name="SessionId">The session of the client, when the server tracks sessions (#57).</param>
public sealed record ClientContext(string Protocol, string? RemoteIp, string? SessionId = null);
