using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace FxSshSftpServer.Pages.Client
{
    /// <summary>
    /// The password change of the web client, also the forced one after a login with an expired password (#61): until
    /// then the login can open only this page and the logout.
    /// </summary>
    [Authorize(Policy = ClientAuth.PasswordChangePolicy)]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class ChangePasswordModel : PageModel
    {
        private readonly ClientPasswordChange _change;
        private readonly ClientAccountService _account;

        public ChangePasswordModel(ClientPasswordChange change, ClientAccountService account)
        {
            _change = change;
            _account = account;
        }

        /// <summary>The external provider that manages the password (#64): then there is no form.</summary>
        public string ManagedBy { get; private set; }

        [BindProperty, DataType(DataType.Password)]
        public string CurrentPassword { get; set; }

        [BindProperty, DataType(DataType.Password)]
        public string NewPassword { get; set; }

        [BindProperty, DataType(DataType.Password)]
        public string RepeatPassword { get; set; }

        public string ErrorMessage { get; private set; }

        public bool MustChange => ClientClaims.MustChangePassword(User);

        public IActionResult OnGet()
        {
            ManagedBy = _account.PasswordManagedBy(User.Identity!.Name);
            if (ManagedBy != null)
                ErrorMessage = SshServer.Interfaces.Authentication.ExternalCredentials.PasswordManagedMessage(ManagedBy);
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            ManagedBy = _account.PasswordManagedBy(User.Identity!.Name);
            if (ManagedBy != null)
            {
                ErrorMessage = SshServer.Interfaces.Authentication.ExternalCredentials.PasswordManagedMessage(ManagedBy);
                ModelState.Clear();
                return new PageResult { StatusCode = StatusCodes.Status403Forbidden };
            }
            var error = await _change.ChangeAsync(HttpContext, CurrentPassword, NewPassword, RepeatPassword);
            if (error == null)
                return LocalRedirect(MustChange ? ClientAuth.BasePath : "/client/account?changed=password");
            ErrorMessage = error;
            CurrentPassword = NewPassword = RepeatPassword = null;
            ModelState.Clear();
            return new PageResult { StatusCode = error == LoginModel.LockedOutMessage ? StatusCodes.Status429TooManyRequests : StatusCodes.Status200OK };
        }
    }
}
