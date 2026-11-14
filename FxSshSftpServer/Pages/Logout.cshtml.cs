using System.Threading.Tasks;
using FxSshSftpServer.Security.Oidc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace FxSshSftpServer.Pages
{
    /// <summary>GET shows a confirmation form; the POST (with antiforgery token) ends the session.</summary>
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class LogoutModel : PageModel
    {
        public void OnGet()
        {
        }

        /// <summary>Ends the local session; after an OpenID Connect sign-in (#73) also the session at the provider, when it offers a logout.</summary>
        public async Task<IActionResult> OnPostAsync()
        {
            var user = User;
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (OidcSignInSetup.SignedInWith(user, OidcSignInSetup.AdminScheme)
                && await OidcSignInSetup.SignOutAtProviderAsync(HttpContext, OidcSignInSetup.AdminScheme, "/Login"))
                return new EmptyResult();
            return LocalRedirect("/Login");
        }
    }
}
