using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using FxSshSftpServer.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Admins;

namespace FxSshSftpServer.Pages
{
    /// <summary>
    /// The signed-in administrator sets a new password (with the current one). The login cookie is issued again, so
    /// this session goes on and every other session of the administrator ends (its stamp changed).
    /// </summary>
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class ChangePasswordModel : PageModel
    {
        public const string MismatchMessage = "The new passwords do not match.";

        private readonly AdminAdministrationService _administration;
        private readonly LoginThrottle _throttle;
        private readonly ILogger<ChangePasswordModel> _logger;

        public ChangePasswordModel(AdminAdministrationService administration, LoginThrottle throttle, ILogger<ChangePasswordModel> logger)
        {
            _administration = administration;
            _throttle = throttle;
            _logger = logger;
        }

        [BindProperty]
        [DataType(DataType.Password)]
        public string CurrentPassword { get; set; }

        [BindProperty]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; }

        [BindProperty]
        [DataType(DataType.Password)]
        public string RepeatPassword { get; set; }

        [BindProperty(SupportsGet = true)]
        public string ReturnUrl { get; set; }

        public string ErrorMessage { get; private set; }

        public bool MustChange => AdminClaims.MustChangePassword(User);

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var client = HttpContext.Connection.RemoteIpAddress?.ToString();
            if (_throttle.IsLockedOut(client))
                return Failed(LoginModel.LockedOutMessage, StatusCodes.Status429TooManyRequests);
            if (!string.Equals(NewPassword, RepeatPassword, System.StringComparison.Ordinal))
                return Failed(MismatchMessage, StatusCodes.Status200OK);

            Admin admin;
            try
            {
                admin = await _administration.ChangeOwnPasswordAsync(User.Identity?.Name ?? "", CurrentPassword, NewPassword, HttpContext.RequestAborted);
            }
            catch (AdminAccessDeniedException ex)
            {
                _throttle.RecordFailure(client);
                _logger.LogWarning("Admin {UserName} gave a wrong current password from {Client}.", User.Identity?.Name, client);
                return Failed(ex.Message, StatusCodes.Status200OK);
            }
            catch (AdminAdministrationException ex)
            {
                return Failed(ex.Message, StatusCodes.Status200OK);
            }

            _logger.LogInformation("Admin {UserName} changed the password.", admin.Username);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, AdminClaims.CreatePrincipal(admin));
            return LocalRedirect(Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : "/");
        }

        private IActionResult Failed(string message, int statusCode)
        {
            ErrorMessage = message;
            CurrentPassword = NewPassword = RepeatPassword = null;
            ModelState.Clear();
            return new PageResult { StatusCode = statusCode };
        }
    }
}
