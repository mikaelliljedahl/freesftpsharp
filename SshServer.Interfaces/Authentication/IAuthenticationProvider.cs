namespace SshServer.Interfaces.Authentication;

/// <summary>
/// A source that checks the credential of a login (issue #64): the local database (the default), an external HTTP
/// service, an LDAP directory. The providers run in the configured order (<see cref="IUserAuthenticator"/>); the first
/// <see cref="AuthOutcome.Success"/> or <see cref="AuthOutcome.Failure"/> wins, <see cref="AuthOutcome.NotHandled"/>
/// asks the next one.
/// <para>
/// A stored user belongs to one provider (<see cref="User.AuthenticationProvider"/>, null: the database), and only that
/// provider is asked for it. A user that is not stored yet can be created by the first provider that accepts it ("just
/// in time"), from the <see cref="ExternalUser"/> of its result. The core still checks the status, the expiry, the
/// session limit, the networks and the login methods of the user (with its groups) for every login.
/// </para>
/// <para>
/// A provider never logs the password, fails closed (an error is a <see cref="AuthOutcome.Failure"/>, not an exception
/// that lets the login through) and keeps to a timeout of its own.
/// </para>
/// </summary>
public interface IAuthenticationProvider
{
    /// <summary>
    /// The unique name (for example "database", "http", "ldap"): the name in <c>Auth:Providers</c>, in the log, and in
    /// <see cref="User.AuthenticationProvider"/> of the users it creates.
    /// </summary>
    string Name { get; }

    /// <summary>Checks the credential of <paramref name="request"/>.</summary>
    ValueTask<AuthResult> AuthenticateAsync(AuthRequest request, CancellationToken ct);
}
