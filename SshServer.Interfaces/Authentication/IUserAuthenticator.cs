namespace SshServer.Interfaces.Authentication;

/// <summary>
/// The credential check of every protocol (issue #64): runs the <see cref="IAuthenticationProvider"/>s in the
/// configured order and prepares the users that an external provider returns. A protocol uses it like this:
/// <list type="number">
/// <item>Read the stored user; when there is one, check the lifecycle (<c>UserLoginRules</c>), the networks and the
/// methods of the user (<c>IEffectiveUserSettingsService</c>). A refusal calls <see cref="SpendFailureTimeAsync"/>, so
/// it takes the time of a wrong password.</item>
/// <item><see cref="VerifyAsync"/>. When the result has <see cref="CredentialCheck.NeedsSave"/>, run the checks of
/// step 1 again with <see cref="CredentialCheck.User"/> (a new user, or new groups).</item>
/// <item>Call <see cref="Save"/> when the login (step) is complete: for an SSH public key only after the signature
/// check, so a public key alone never creates or changes a user.</item>
/// </list>
/// With only the database provider (the default), this is the check of the stored password or key.
/// </summary>
public interface IUserAuthenticator
{
    /// <summary>
    /// True when a provider other than the database is used: then a user name that is not stored can still log in, and
    /// the protocol asks <see cref="VerifyAsync"/> for it.
    /// </summary>
    bool HasExternalProviders { get; }

    /// <summary>Checks the credential with the providers. Never throws for a provider error (fail closed).</summary>
    ValueTask<CredentialCheck> VerifyAsync(AuthRequest request, CancellationToken ct);

    /// <summary>
    /// Takes the time of a failed credential check, for a login that is refused before the check (status, expiry,
    /// networks, method). Does nothing for a public key.
    /// </summary>
    ValueTask SpendFailureTimeAsync(AuthRequest request, CancellationToken ct);

    /// <summary>
    /// Saves the user of a <see cref="CredentialCheck"/> with <see cref="CredentialCheck.NeedsSave"/>. False when it
    /// cannot be saved (then refuse the login).
    /// </summary>
    bool Save(CredentialCheck check);
}

/// <summary>
/// The result of <see cref="IUserAuthenticator.VerifyAsync"/>. <see cref="User"/> is the user to log in: the stored one,
/// or (with <see cref="NeedsSave"/>) a copy created or changed from the definition of the provider, not saved yet.
/// </summary>
public sealed record CredentialCheck(bool Succeeded, string? Reason, string? Provider, User? User, bool NeedsSave)
{
    public static CredentialCheck Failed(string reason, string? provider = null) => new(false, reason, provider, null, false);
}
