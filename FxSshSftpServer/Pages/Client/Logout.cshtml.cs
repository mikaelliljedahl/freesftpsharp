using System.Threading.Tasks;
using FxSshSftpServer.Security.Oidc;
using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace FxSshSftpServer.Pages.Client
{
    /// <summary>
    /// The POST (with antiforgery token) ends the browser session: its connection, its uploads and the cookie. After an
    /// OpenID Connect sign-in (#73) the page then continues to the logout at the provider (<see cref="ProviderLogoutModel"/>)
    /// with a meta refresh: the strict <c>form-action</c> of the client pages does not allow the redirect of a form
    /// submission to another site.
    /// </summary>
    [Authorize(Policy = ClientAuth.PasswordChangePolicy)]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class LogoutModel : PageModel
    {
        public const string ProviderLogoutPath = ProviderLogoutModel.Path;

        private readonly ClientSessions _sessions;

        public LogoutModel(ClientSessions sessions, Microsoft.Extensions.Options.IOptions<ClientOidcOptions> oidc)
        {
            _sessions = sessions;
            ProviderName = oidc.Value.DisplayName;
        }

        public string ProviderName { get; }

        /// <summary>True after the local logout of a user of the OpenID Connect sign-in: the page goes on to the provider.</summary>
        public bool ProviderLogout { get; private set; }

        public IActionResult OnGet() => LocalRedirect(ClientAuth.BasePath);

        public async Task<IActionResult> OnPostAsync()
        {
            var user = User;
            if (ClientClaims.Session(user) is { } session)
                _sessions.End(session);
            await HttpContext.SignOutAsync(ClientAuth.Scheme);
            if (OidcSignInSetup.SignedInWith(user, OidcSignInSetup.ClientScheme) && await OidcSignInSetup.IsEnabledAsync(HttpContext, OidcSignInSetup.ClientScheme))
            {
                ProviderLogout = true;
                return Page();
            }
            return LocalRedirect(ClientAuth.LoginPath);
        }
    }
}
