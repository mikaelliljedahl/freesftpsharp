namespace SshServer.Interfaces.Authentication;

/// <summary>What an <see cref="IAuthenticationProvider"/> decided.</summary>
public enum AuthOutcome
{
    /// <summary>The provider does not know the user (or the method): the next provider is asked.</summary>
    NotHandled,

    /// <summary>The credential is right.</summary>
    Success,

    /// <summary>The credential is wrong, or the provider could not check it (fail closed). No other provider is asked.</summary>
    Failure,
}

/// <summary>
/// The result of one provider. <see cref="Reason"/> is for the log and the audit events, never for the client.
/// <see cref="User"/> is the user definition of an external provider: the user is created or updated with it.
/// </summary>
public sealed record AuthResult(AuthOutcome Outcome, string? Reason = null, ExternalUser? User = null)
{
    public static AuthResult NotHandled { get; } = new(AuthOutcome.NotHandled);

    public static AuthResult Success(ExternalUser? user = null) => new(AuthOutcome.Success, null, user);

    public static AuthResult Failure(string reason) => new(AuthOutcome.Failure, reason);
}
