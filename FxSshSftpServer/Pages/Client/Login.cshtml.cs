using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.TwoFactor;

namespace FxSshSftpServer.Pages.Client
{
    /// <summary>
    /// The login of the web client (#69): the user name and password through <see cref="IClientCredentialVerifier"/>,
    /// then the code of the second factor (<see cref="LoginCodeModel"/>) for a user with TOTP. Razor Pages check the
    /// antiforgery token of every POST; the failures count for <see cref="ClientLoginThrottle"/>.
    /// </summary>
    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class LoginModel : PageModel
    {
        public const string InvalidCredentialsMessage = "Invalid user name or password.";
        public const string LockedOutMessage = "Too many failed logins. Try again later.";

        private readonly IClientCredentialVerifier _verifier;
        private readonly ClientLoginThrottle _throttle;
        private readonly ClientLoginFlow _flow;
        private readonly ITwoFactorVerifier _twoFactor;
        private readonly ClientPendingLogin _pending;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(IClientCredentialVerifier verifier, ClientLoginThrottle throttle, ClientLoginFlow flow, ITwoFactorVerifier twoFactor,
            ClientPendingLogin pending, ILogger<LoginModel> logger)
        {
            _verifier = verifier;
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

        public async Task<IActionResult> OnGetAsync()
        {
            var current = await HttpContext.AuthenticateAsync(ClientAuth.Scheme);
            if (current.Succeeded && ClientClaims.Session(current.Principal) != null)
                return LocalRedirect(ClientAuth.BasePath);
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var client = HttpContext.Connection.RemoteIpAddress?.ToString();
            _pending.Clear(HttpContext);

            if (_throttle.Throttle.IsLockedOut(client))
            {
                _logger.LogWarning("Web client login refused for {Client}: locked out after too many failures.", client);
                return Failed(LockedOutMessage, StatusCodes.Status429TooManyRequests);
            }

            var result = await _verifier.VerifyAsync(UserName, Password, HttpContext.Connection.RemoteIpAddress, HttpContext.RequestAborted);
            if (result.User is not { } user)
            {
                _throttle.Throttle.RecordFailure(client);
                _logger.LogWarning("Failed web client login for user {UserName} from {Client}: {Reason}.", UserName, client, result.FailureReason);
                await _flow.PublishFailedAsync(HttpContext, UserName, "password", result.FailureReason);
                return Failed(InvalidCredentialsMessage, StatusCodes.Status200OK);
            }

            if (await _twoFactor.IsEnabledAsync(TwoFactorSubject.ForUser(user), HttpContext.RequestAborted))
            {
                // The throttle is not reset here: the failures of the code step count with the password failures.
                _pending.Issue(HttpContext, user, result.PasswordExpired);
                var code = "/client/logincode";
                return LocalRedirect(string.IsNullOrEmpty(ReturnUrl) ? code : code + "?ReturnUrl=" + Uri.EscapeDataString(ReturnUrl));
            }

            return await _flow.CompleteAsync(this, user, "password", result.PasswordExpired, ReturnUrl)
                   ?? Failed(ClientLoginFlow.TooManySessionsMessage, StatusCodes.Status200OK);
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
