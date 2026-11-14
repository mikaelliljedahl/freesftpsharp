namespace SshServer.Administration
{
    /// <summary>
    /// Whether the administrators may log in with their local password: the login page of the admin UI and the token
    /// endpoint of the REST API (#67) both ask it. The web host turns it off with
    /// <c>Auth:Oidc:Admin:DisableLocalLogin</c> (#73); without a registration the password login is allowed.
    /// </summary>
    public interface IAdminPasswordLoginPolicy
    {
        bool PasswordLoginAllowed { get; }
    }
}
