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
using System.Net;
using FxSsh.SshServerModule.Security;
using SshServer.Interfaces.Authentication;

namespace FxSshSftpServer.Pages.Client
{
    /// <summary>
    /// The login of the web client (#69): the user name and password through the <see cref="PasswordLoginService"/> of
    /// the protocols (global IP rules, auto-ban, lifecycle, allowed networks and methods, the protocol flag
    /// <see cref="UserProtocols.Web"/>, the auth events), then the code of the second factor (<see cref="LoginCodeModel"/>) for a user with TOTP. Razor Pages check the
    /// antiforgery token of every POST; the failures count for <see cref="ClientLoginThrottle"/>.
    /// </summary>
    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class LoginModel : PageModel
    {
        public const string InvalidCredentialsMessage = "Invalid user name or password.";
        public const string LockedOutMessage = "Too many failed logins. Try again later.";
        public const string ProtocolNotAllowedMessage = "Your account may not use the web client.";

        private readonly PasswordLoginService _login;
        private readonly ClientLoginThrottle _throttle;
        private readonly ClientLoginFlow _flow;
        private readonly ClientPendingLogin _pending;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(PasswordLoginService login, ClientLoginThrottle throttle, ClientLoginFlow flow,
            ClientPendingLogin pending, ILogger<LoginModel> logger)
        {
            _login = login;
            _throttle = throttle;
            _flow = flow;
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

            var remote = HttpContext.Connection.RemoteIpAddress ?? IPAddress.Loopback; // TestServer has no address
            // The service logs the failure (with LogText.Clean), publishes LoginFailed (protocol HTTP) and counts it for the auto-ban.
            var result = await _login.LoginAsync(ClientAuth.Protocol, UserProtocols.Web, UserName?.Trim(), Password, remote,
                HttpContext.RequestAborted, PasswordLoginOptions.Interactive);
            if (result.Status == PasswordLoginStatus.ProtocolNotAllowed)
                return Failed(ProtocolNotAllowedMessage, StatusCodes.Status403Forbidden);
            if (result.Status != PasswordLoginStatus.Ok || result.User is not { } user)
            {
                _throttle.Throttle.RecordFailure(client);
                return Failed(InvalidCredentialsMessage, StatusCodes.Status200OK);
            }

            if (result.SecondFactorRequired)
            {
                // The throttle is not reset here: the failures of the code step count with the password failures.
                _pending.Issue(HttpContext, user, result.PasswordExpired);
                var code = "/client/logincode";
                return LocalRedirect(string.IsNullOrEmpty(ReturnUrl) ? code : code + "?ReturnUrl=" + Uri.EscapeDataString(ReturnUrl));
            }

            return await _flow.CompleteAsync(this, user, result.Method, result.PasswordExpired, ReturnUrl)
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
