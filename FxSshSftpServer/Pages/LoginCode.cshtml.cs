using System.Threading.Tasks;
using FxSshSftpServer.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.TwoFactor;

namespace FxSshSftpServer.Pages
{
    /// <summary>
    /// The second step of the admin login (#63): the verification code of the authenticator app, or a recovery code,
    /// after the right password on <see cref="LoginModel"/>. The failures count for the same lockout as wrong passwords
    /// (<see cref="LoginThrottle"/>), and for the per-administrator limit of the two-factor service.
    /// </summary>
    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class LoginCodeModel : PageModel
    {
        public const string InvalidCodeMessage = "Invalid verification code.";
        public const string TooManyCodesMessage = "Too many wrong codes. Try again later.";

        private readonly PendingTwoFactorLogin _pending;
        private readonly IAdminStore _admins;
        private readonly ITwoFactorVerifier _twoFactor;
        private readonly LoginThrottle _throttle;
        private readonly AdminLoginFlow _flow;
        private readonly ILogger<LoginCodeModel> _logger;

        public LoginCodeModel(PendingTwoFactorLogin pending, IAdminStore admins, ITwoFactorVerifier twoFactor, LoginThrottle throttle,
            AdminLoginFlow flow, ILogger<LoginCodeModel> logger)
        {
            _pending = pending;
            _admins = admins;
            _twoFactor = twoFactor;
            _throttle = throttle;
            _flow = flow;
            _logger = logger;
        }

        [BindProperty]
        public string Code { get; set; }

        [BindProperty(SupportsGet = true)]
        public string ReturnUrl { get; set; }

        public string ErrorMessage { get; private set; }

        public async Task<IActionResult> OnGetAsync()
        {
            return await PendingAdminAsync() == null ? BackToLogin() : Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var client = HttpContext.Connection.RemoteIpAddress?.ToString();
            if (_throttle.IsLockedOut(client))
            {
                _logger.LogWarning("Admin verification code refused for {Client}: locked out after too many failures.", client);
                return Failed(LoginModel.LockedOutMessage, StatusCodes.Status429TooManyRequests);
            }

            var admin = await PendingAdminAsync();
            if (admin == null)
                return BackToLogin();

            var check = await _twoFactor.VerifyAsync(TwoFactorSubject.ForAdmin(admin), Code, HttpContext.RequestAborted);
            switch (check)
            {
                case TwoFactorCheck.Valid:
                    _pending.Clear(HttpContext);
                    return await _flow.CompleteAsync(this, admin, "password,totp", ReturnUrl);
                case TwoFactorCheck.RecoveryCode:
                    _pending.Clear(HttpContext);
                    _logger.LogWarning("Admin {UserName} used a recovery code from {Client}.", admin.Username, client);
                    return await _flow.CompleteAsync(this, admin, "password,recovery-code", ReturnUrl);
                case TwoFactorCheck.NotEnabled:
                    // The second factor was reset after the password step: log in again (then without a code).
                    return BackToLogin();
            }

            _throttle.RecordFailure(client);
            _logger.LogWarning("Wrong verification code for admin {UserName} from {Client}: {Result}.", admin.Username, client, check);
            await _flow.PublishFailedAsync(HttpContext, admin.Username, "password,totp", check switch
            {
                TwoFactorCheck.Replayed => "the verification code was used already",
                TwoFactorCheck.LockedOut => "too many wrong verification codes",
                _ => "wrong verification code",
            });
            return check == TwoFactorCheck.LockedOut
                ? Failed(TooManyCodesMessage, StatusCodes.Status429TooManyRequests)
                : Failed(InvalidCodeMessage, StatusCodes.Status200OK);
        }

        /// <summary>The administrator of the pending login, when it still exists unchanged, is enabled and may use this address.</summary>
        private async Task<Admin> PendingAdminAsync()
        {
            var pending = _pending.Read(HttpContext);
            if (pending is not { } state)
                return null;
            var admin = await _admins.GetAdminAsync(state.Username, HttpContext.RequestAborted);
            if (admin == null || admin.Status != AdminStatus.Enabled || AdminClaims.Stamp(admin) != state.Stamp
                || !AdminClaims.IsAddressAllowed(admin, HttpContext.Connection.RemoteIpAddress))
                return null;
            return admin;
        }

        private IActionResult BackToLogin()
        {
            _pending.Clear(HttpContext);
            var login = "/Login";
            return LocalRedirect(Url.IsLocalUrl(ReturnUrl) ? login + "?ReturnUrl=" + System.Uri.EscapeDataString(ReturnUrl) : login);
        }

        private IActionResult Failed(string message, int statusCode)
        {
            ErrorMessage = message;
            Code = null;
            ModelState.Remove(nameof(Code));
            return new PageResult { StatusCode = statusCode };
        }
    }
}
