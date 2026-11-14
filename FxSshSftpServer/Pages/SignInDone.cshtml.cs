using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace FxSshSftpServer.Pages
{
    /// <summary>
    /// The page after an OpenID Connect sign-in to the admin UI (#73, <c>/signin-done</c>). The provider posts the code
    /// cross-site, so the browser does not send the SameSite=Strict login cookie on the redirect that follows; this page
    /// continues to <see cref="Target"/> with a meta refresh, a same-site navigation that sends it.
    /// </summary>
    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class SignInDoneModel : PageModel
    {
        [BindProperty(SupportsGet = true)]
        public string ReturnUrl { get; set; }

        public string Target { get; private set; } = "/";

        public void OnGet()
        {
            Target = Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : "/";
        }
    }
}
