using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using FxSshSftpServer.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Events;

namespace FxSshSftpServer.Pages
{
    /// <summary>Login for the stored administrators. Razor Pages validate the antiforgery token of every POST.</summary>
    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class LoginModel : PageModel
    {
        public const string InvalidCredentialsMessage = "Invalid user name or password.";
        public const string LockedOutMessage = "Too many failed logins. Try again later.";

        /// <summary>The <see cref="AuthEvent.Protocol"/> of the admin logins in the audit log.</summary>
        public const string AuditProtocol = "AdminUI";

        private readonly AdminCredentialValidator _validator;
        private readonly AdminAdministrationService _administration;
        private readonly LoginThrottle _throttle;
        private readonly IEventBus _events;
        private readonly System.TimeProvider _time;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(AdminCredentialValidator validator, AdminAdministrationService administration, LoginThrottle throttle,
            IEventBus events, System.TimeProvider time, ILogger<LoginModel> logger)
        {
            _validator = validator;
            _administration = administration;
            _throttle = throttle;
            _events = events;
            _time = time;
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
                await PublishAsync(AuthEventType.LoginFailed, UserName, client);
                return Failed(InvalidCredentialsMessage, StatusCodes.Status200OK);
            }

            _throttle.RecordSuccess(client);
            _logger.LogInformation("Admin {UserName} logged in from {Client}.", admin.Username, client);
            await _administration.RecordLoginAsync(admin, HttpContext.RequestAborted);
            await PublishAsync(AuthEventType.LoginOk, admin.Username, client);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, AdminClaims.CreatePrincipal(admin));

            var target = Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : "/";
            if (admin.MustChangePassword)
                return LocalRedirect("/ChangePassword?ReturnUrl=" + System.Uri.EscapeDataString(target));
            return LocalRedirect(target);
        }

        private async Task PublishAsync(AuthEventType type, string userName, string client)
        {
            await _events.PublishAsync(new AuthEvent(type)
            {
                Timestamp = _time.GetUtcNow(),
                Username = userName?.Trim(),
                RemoteIp = client,
                Protocol = AuditProtocol,
                Method = "password",
                Reason = type == AuthEventType.LoginFailed ? "wrong user name or password, disabled account or address not allowed" : null,
            }, HttpContext.RequestAborted);
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
