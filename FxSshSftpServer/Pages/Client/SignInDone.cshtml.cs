using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace FxSshSftpServer.Pages.Client
{
    /// <summary>
    /// The page after an OpenID Connect sign-in to the web client (#73, <c>/client/signin-done</c>): continues to
    /// <see cref="Target"/> with a meta refresh, a same-site navigation, so the browser sends the SameSite=Strict login
    /// cookie that it does not send on the redirect after the cross-site <c>form_post</c> of the provider.
    /// </summary>
    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class SignInDoneModel : PageModel
    {
        [BindProperty(SupportsGet = true)]
        public string ReturnUrl { get; set; }

        public string Target { get; private set; } = ClientAuth.BasePath;

        public void OnGet()
        {
            Target = ClientLoginFlow.IsClientUrl(this, ReturnUrl) ? ReturnUrl : ClientAuth.BasePath;
        }
    }
}
