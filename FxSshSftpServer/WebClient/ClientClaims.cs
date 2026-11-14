using System;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using SshServer.Interfaces;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The login of an SFTP user in the web client (#69): its own cookie scheme, separate from the admin cookie. The
    /// cookie is sent only for <see cref="CookiePath"/>, and only the <c>/client</c> endpoints accept the scheme, so an
    /// admin cookie never opens the client and a client cookie never opens the admin UI.
    /// </summary>
    public static class ClientAuth
    {
        public const string Scheme = "UserAuth";
        public const string CookieName = ".FxSshSftpServer.Client";
        public const string BasePath = "/client";
        public const string CookiePath = BasePath;
        public const string LoginPath = "/client/login";
        public const string ApiPath = "/client/api";

        /// <summary>A signed-in user (not in the forced password change).</summary>
        public const string UserPolicy = "WebClientUser";

        /// <summary>A signed-in user, also one that must change an expired password first.</summary>
        public const string PasswordChangePolicy = "WebClientPasswordChange";

        /// <summary>The <c>AuthEvent.Protocol</c> and the <c>ClientContext.Protocol</c> of the web client.</summary>
        public const string Protocol = SshServer.Interfaces.Connections.ConnectionProtocols.Http;
    }

    /// <summary>
    /// The claims of a web client login: the user name, the session (the id of its connection in the connection
    /// registry) and a stamp of the security fields of the user. The cookie handler compares the stamp with the stored
    /// user on every request, so a new password, a disabled or removed user ends the session.
    /// </summary>
    public static class ClientClaims
    {
        public const string SessionClaim = "freesftpsharp:client_session";
        public const string StampClaim = "freesftpsharp:client_stamp";
        public const string MustChangePasswordClaim = "freesftpsharp:client_must_change_password";
        public const string Role = "SftpUser";

        /// <param name="identityProvider">The scheme of an OpenID Connect sign-in (#73), for the logout at the provider; null for a password login.</param>
        public static ClaimsPrincipal CreatePrincipal(User user, Guid session, bool mustChangePassword, string identityProvider = null)
        {
            var identity = new ClaimsIdentity(ClientAuth.Scheme);
            identity.AddClaim(new Claim(ClaimTypes.Name, user.Username));
            identity.AddClaim(new Claim(ClaimTypes.Role, Role));
            identity.AddClaim(new Claim(SessionClaim, session.ToString("D")));
            identity.AddClaim(new Claim(StampClaim, Stamp(user)));
            if (mustChangePassword)
                identity.AddClaim(new Claim(MustChangePasswordClaim, "true"));
            if (!string.IsNullOrEmpty(identityProvider))
                identity.AddClaim(new Claim(Security.Oidc.OidcClaims.IdentityProviderClaim, identityProvider));
            return new ClaimsPrincipal(identity);
        }

        /// <summary>The session of a web client principal, or null when it is not one.</summary>
        public static Guid? Session(ClaimsPrincipal user) =>
            user?.Identity is { IsAuthenticated: true, AuthenticationType: ClientAuth.Scheme }
            && user.IsInRole(Role)
            && Guid.TryParseExact(user.FindFirstValue(SessionClaim), "D", out var id)
                ? id
                : null;

        public static bool MustChangePassword(ClaimsPrincipal user) => user?.HasClaim(MustChangePasswordClaim, "true") == true;

        /// <summary>A hash of the fields that decide whether the login is still valid. It changes when one of them changes.</summary>
        public static string Stamp(User user)
        {
            var text = string.Join('\n', user.Id.ToString(CultureInfo.InvariantCulture), user.Username.ToLowerInvariant(),
                user.HashedPassword ?? "", user.Status);
            return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        }
    }
}
