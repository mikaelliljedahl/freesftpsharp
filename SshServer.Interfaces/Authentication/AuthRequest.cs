namespace SshServer.Interfaces.Authentication;

/// <summary>
/// One credential to check (issue #64): a password (<see cref="Password"/>, also the password step of
/// keyboard-interactive) or a public key (<see cref="PublicKey"/>). <see cref="ToString"/> never shows the password.
/// </summary>
public sealed class AuthRequest
{
    /// <summary>The user name the client sent.</summary>
    public required string Username { get; init; }

    /// <summary>The login method of the request: <see cref="AuthMethods.Password"/>, <see cref="AuthMethods.PublicKey"/> or <see cref="AuthMethods.KeyboardInteractive"/>.</summary>
    public required AuthMethods Method { get; init; }

    /// <summary>The password; null for a public key.</summary>
    public string? Password { get; init; }

    /// <summary>
    /// The SSH public key blob of the request (RFC 4253 section 6.6); null for a password. For an SSH public key login the
    /// provider is asked before the client proves that it has the private key; the server checks the signature after an
    /// accepted key, and a user that the provider returns is saved only after that check.
    /// </summary>
    public byte[]? PublicKey { get; init; }

    /// <summary>The address of the client (IPv4 clients of the dual-stack listener as IPv4), or null.</summary>
    public string? RemoteIp { get; init; }

    /// <summary>The protocol of the login, for example "SSH".</summary>
    public required string Protocol { get; init; }

    /// <summary>The stored user with this name, or null when there is none.</summary>
    public User? StoredUser { get; init; }

    /// <summary>True for a password (also over keyboard-interactive): a refusal costs the time of a password check.</summary>
    public bool IsPassword => Password != null;

    public override string ToString() => $"{Method} login of {Username} from {RemoteIp ?? "?"} ({Protocol})";
}
