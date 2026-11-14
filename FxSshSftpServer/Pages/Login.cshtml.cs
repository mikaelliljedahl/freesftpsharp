using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using FxSshSftpServer.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.TwoFactor;

namespace FxSshSftpServer.Pages
{
    /// <summary>
    /// Login for the stored administrators. Razor Pages validate the antiforgery token of every POST. An administrator
    /// with a second factor (#63) continues on <see cref="LoginCodeModel"/> after the right password.
    /// </summary>
    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class LoginModel : PageModel
    {
        public const string InvalidCredentialsMessage = "Invalid user name or password.";
        public const string LockedOutMessage = "Too many failed logins. Try again later.";

        /// <summary>The <see cref="AuthEvent.Protocol"/> of the admin logins in the audit log.</summary>
        public const string AuditProtocol = AdminLoginFlow.AuditProtocol;

        private readonly AdminCredentialValidator _validator;
        private readonly LoginThrottle _throttle;
        private readonly AdminLoginFlow _flow;
        private readonly ITwoFactorVerifier _twoFactor;
        private readonly PendingTwoFactorLogin _pending;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(AdminCredentialValidator validator, LoginThrottle throttle, AdminLoginFlow flow, ITwoFactorVerifier twoFactor,
            PendingTwoFactorLogin pending, ILogger<LoginModel> logger)
        {
            _validator = validator;
            _throttle = throttle;
            _flow = flow;
            _twoFactor = twoFactor;
            _pending = pending;
            _logger = logger;
        }

        [BindProperty]
        public string UserName { get; set; }

        [BindProperty]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [BindProperty(SupportsGet = true)]
        public string ReturnUrl { get; set; }

        public string ErrorMessage { get; private set; }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var client = HttpContext.Connection.RemoteIpAddress?.ToString();
            _pending.Clear(HttpContext);

            if (_throttle.IsLockedOut(client))
            {
                _logger.LogWarning("Admin login refused for {Client}: locked out after too many failures.", client);
                return Failed(LockedOutMessage, StatusCodes.Status429TooManyRequests);
            }

            var admin = await _validator.ValidateAsync(UserName, Password, HttpContext.Connection.RemoteIpAddress, HttpContext.RequestAborted);
            if (admin == null)
            {
                _throttle.RecordFailure(client);
                _logger.LogWarning("Failed admin login for user {UserName} from {Client}.", UserName, client);
                await _flow.PublishFailedAsync(HttpContext, UserName, "password",
                    "wrong user name or password, disabled account or address not allowed");
                return Failed(InvalidCredentialsMessage, StatusCodes.Status200OK);
            }

            if (await _twoFactor.IsEnabledAsync(TwoFactorSubject.ForAdmin(admin), HttpContext.RequestAborted))
            {
                // The throttle is not reset here: the failures of the code step count with the password failures.
                _pending.Issue(HttpContext, admin);
                _logger.LogInformation("Admin {UserName} gave the right password from {Client}; the verification code is next.", admin.Username, client);
                var code = "/LoginCode";
                return LocalRedirect(string.IsNullOrEmpty(ReturnUrl) ? code : code + "?ReturnUrl=" + System.Uri.EscapeDataString(ReturnUrl));
            }

            return await _flow.CompleteAsync(this, admin, "password", ReturnUrl);
        }

        private IActionResult Failed(string message, int statusCode)
        {
            ErrorMessage = message;
            Password = null;
            ModelState.Remove(nameof(Password));
            return new PageResult { StatusCode = statusCode };
        }
    }
}
