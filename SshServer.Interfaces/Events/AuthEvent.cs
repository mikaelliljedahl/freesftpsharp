namespace SshServer.Interfaces.Events;

/// <summary>The type of an <see cref="AuthEvent"/>.</summary>
public enum AuthEventType
{
    LoginOk,
    LoginFailed,
    Logout,
    IpBanned,
    IpUnbanned,

    /// <summary>
    /// A sign-in through an identity provider (OpenID Connect, #73), after its <see cref="LoginOk"/>: an event rule (#68)
    /// can adjust the account. <see cref="AuthEvent.Method"/> is "oidc".
    /// </summary>
    IdpLogin,
}

/// <summary>A login, a logout or an IP ban.</summary>
/// <param name="Type">What happened.</param>
public sealed record AuthEvent(AuthEventType Type) : IEvent
{
    public EventCategory Category => EventCategory.Auth;

    public string TypeName => Type.ToString();

    public DateTimeOffset Timestamp { get; init; }

    /// <summary>The user name the client gave; null for a ban.</summary>
    public string? Username { get; init; }

    public string? RemoteIp { get; init; }

    /// <summary>The protocol, for example "SSH".</summary>
    public string Protocol { get; init; } = string.Empty;

    /// <summary>The authentication method, for example "password" or "publickey".</summary>
    public string? Method { get; init; }

    /// <summary>Why a login failed, or why an address was banned.</summary>
    public string? Reason { get; init; }

    /// <summary>The session of the client, when the server tracks sessions (#57).</summary>
    public string? SessionId { get; init; }
}
