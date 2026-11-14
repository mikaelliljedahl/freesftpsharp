using System;
using System.Threading.Tasks;
using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.TwoFactor;
using SshServer.Interfaces.Users;

namespace FxSshSftpServer.Pages.Client
{
    /// <summary>
    /// The second step of a web client login (#63): the TOTP code or a recovery code after the right password. The
    /// failures count for the same lockout as wrong passwords, and for the per-user limit of the two-factor service.
    /// </summary>
    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class LoginCodeModel : PageModel
    {
        public const string InvalidCodeMessage = "Invalid verification code.";
        public const string TooManyCodesMessage = "Too many wrong codes. Try again later.";

        private readonly ClientPendingLogin _pending;
        private readonly ISettingsRepository _repository;
        private readonly ITwoFactorVerifier _twoFactor;
        private readonly ClientLoginThrottle _throttle;
        private readonly ClientLoginFlow _flow;
        private readonly TimeProvider _time;
        private readonly ILogger<LoginCodeModel> _logger;

        public LoginCodeModel(ClientPendingLogin pending, ISettingsRepository repository, ITwoFactorVerifier twoFactor, ClientLoginThrottle throttle,
            ClientLoginFlow flow, TimeProvider time, ILogger<LoginCodeModel> logger)
        {
            _pending = pending;
            _repository = repository;
            _twoFactor = twoFactor;
            _throttle = throttle;
            _flow = flow;
            _time = time;
            _logger = logger;
        }

        [BindProperty]
        public string Code { get; set; }

        [BindProperty(SupportsGet = true)]
        public string ReturnUrl { get; set; }

        public string ErrorMessage { get; private set; }

        public IActionResult OnGet() => PendingUser(out _) == null ? BackToLogin() : Page();

        public async Task<IActionResult> OnPostAsync()
        {
            var client = HttpContext.Connection.RemoteIpAddress?.ToString();
            if (_throttle.Throttle.IsLockedOut(client))
                return Failed(LoginModel.LockedOutMessage, StatusCodes.Status429TooManyRequests);

            var user = PendingUser(out var passwordExpired);
            if (user == null)
                return BackToLogin();

            var check = await _twoFactor.VerifyAsync(TwoFactorSubject.ForUser(user), Code, HttpContext.RequestAborted);
            switch (check)
            {
                case TwoFactorCheck.Valid or TwoFactorCheck.RecoveryCode:
                    _pending.Clear(HttpContext);
                    if (check == TwoFactorCheck.RecoveryCode)
                        _logger.LogWarning("User {Username} used a recovery code in the web client from {Client}.", user.Username, client);
                    var method = check == TwoFactorCheck.Valid ? "password,totp" : "password,recovery-code";
                    return await _flow.CompleteAsync(this, user, method, passwordExpired, ReturnUrl)
                           ?? Failed(ClientLoginFlow.TooManySessionsMessage, StatusCodes.Status200OK);
                case TwoFactorCheck.NotEnabled:
                    return BackToLogin();
            }

            _throttle.Throttle.RecordFailure(client);
            await _flow.PublishFailedAsync(HttpContext, user.Username, "password,totp", check switch
            {
                TwoFactorCheck.Replayed => "the verification code was used already",
                TwoFactorCheck.LockedOut => "too many wrong verification codes",
                _ => "wrong verification code",
            });
            return check == TwoFactorCheck.LockedOut
                ? Failed(TooManyCodesMessage, StatusCodes.Status429TooManyRequests)
                : Failed(InvalidCodeMessage, StatusCodes.Status200OK);
        }

        /// <summary>The user of the pending login, when it still exists unchanged and may log in.</summary>
        private User PendingUser(out bool passwordExpired)
        {
            passwordExpired = false;
            if (_pending.Read(HttpContext) is not { } state)
                return null;
            var user = _repository.GetUser(state.Username);
            if (user == null || ClientClaims.Stamp(user) != state.Stamp || UserLoginRules.IsExpired(user, _time.GetUtcNow().UtcDateTime))
                return null;
            passwordExpired = state.PasswordExpired;
            return user;
        }

        private IActionResult BackToLogin()
        {
            _pending.Clear(HttpContext);
            return LocalRedirect(ClientAuth.LoginPath);
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
