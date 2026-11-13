using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Threading.Tasks;
using FxSshSftpServer.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace FxSshSftpServer.Pages
{
    /// <summary>Login for the local admin account. Razor Pages validate the antiforgery token of every POST.</summary>
    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class LoginModel : PageModel
    {
        public const string InvalidCredentialsMessage = "Invalid user name or password.";
        public const string LockedOutMessage = "Too many failed logins. Try again later.";

        private readonly AdminCredentialValidator _validator;
        private readonly LoginThrottle _throttle;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(AdminCredentialValidator validator, LoginThrottle throttle, ILogger<LoginModel> logger)
        {
            _validator = validator;
            _throttle = throttle;
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

            if (!_validator.Validate(UserName, Password))
            {
                _throttle.RecordFailure(client);
                _logger.LogWarning("Failed admin login for user {UserName} from {Client}.", UserName, client);
                return Failed(InvalidCredentialsMessage, StatusCodes.Status200OK);
            }

            _throttle.RecordSuccess(client);
            _logger.LogInformation("Admin {UserName} logged in from {Client}.", _validator.UserName, client);

            var identity = new ClaimsIdentity(new List<Claim>
            {
                new(ClaimTypes.Name, _validator.UserName),
                new(ClaimTypes.Role, "Admin"),
            }, CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

            return LocalRedirect(Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : "/");
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
