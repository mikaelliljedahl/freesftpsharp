using System.Threading.Tasks;
using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace FxSshSftpServer.Pages.Client
{
    /// <summary>The POST (with antiforgery token) ends the browser session: its connection, its uploads and the cookie.</summary>
    [Authorize(Policy = ClientAuth.PasswordChangePolicy)]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class LogoutModel : PageModel
    {
        private readonly ClientSessions _sessions;

        public LogoutModel(ClientSessions sessions)
        {
            _sessions = sessions;
        }

        public IActionResult OnGet() => LocalRedirect(ClientAuth.BasePath);

        public async Task<IActionResult> OnPostAsync()
        {
            if (ClientClaims.Session(User) is { } session)
                _sessions.End(session);
            await HttpContext.SignOutAsync(ClientAuth.Scheme);
            return LocalRedirect(ClientAuth.LoginPath);
        }
    }
}
