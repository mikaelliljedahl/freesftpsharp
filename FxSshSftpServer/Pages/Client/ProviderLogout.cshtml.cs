using System.Threading.Tasks;
using FxSshSftpServer.Security.Oidc;
using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace FxSshSftpServer.Pages.Client
{
    /// <summary>
    /// The logout at the provider of the OpenID Connect sign-in (#73) after the local logout (<see cref="LogoutModel"/>):
    /// a redirect to its end_session_endpoint when it publishes one, otherwise the login page. The local session is
    /// already gone, so the page needs no login.
    /// </summary>
    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class ProviderLogoutModel : PageModel
    {
        public const string Path = "/client/logout-provider";

        public async Task<IActionResult> OnGetAsync()
        {
            if (await OidcSignInSetup.SignOutAtProviderAsync(HttpContext, OidcSignInSetup.ClientScheme, ClientAuth.LoginPath))
                return new EmptyResult();
            return LocalRedirect(ClientAuth.LoginPath);
        }
    }
}
