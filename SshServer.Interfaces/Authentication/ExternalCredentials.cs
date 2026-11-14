namespace SshServer.Interfaces.Authentication;

/// <summary>
/// The rule for the users of an external authentication provider (#64): their provider checks the password, so a password
/// stored here would never be used. The web client, the admin UI and the REST API refuse to set one, with
/// <see cref="PasswordManagedMessage"/>. The password age (#61) never applies to them: they have no stored password.
/// </summary>
public static class ExternalCredentials
{
    /// <summary>The provider that manages the password of the user, or null for a local user (the database).</summary>
    public static string? PasswordManagedBy(User user) =>
        string.IsNullOrWhiteSpace(user?.AuthenticationProvider) ? null : user.AuthenticationProvider;

    /// <summary>The text for the user or the administrator.</summary>
    public static string PasswordManagedMessage(string provider) => $"The password of this account is managed by {provider}.";
}
