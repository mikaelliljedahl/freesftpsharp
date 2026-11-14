using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FxSshSftpServer.WebClient;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Connections;
using SshServer.TwoFactor;

namespace FxSshSftpServer.Pages.Client
{
    /// <summary>
    /// The account of the signed-in user (#69): the password, the public keys (#58), the second factor (#63) and the open
    /// sessions. Every change goes through <see cref="ClientAccountService"/>, always for the user of the login.
    /// </summary>
    [Authorize(Policy = ClientAuth.UserPolicy)]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class AccountModel : PageModel
    {
        private readonly ClientAccountService _account;

        public AccountModel(ClientAccountService account)
        {
            _account = account;
        }

        [BindProperty]
        public string KeysText { get; set; }

        [BindProperty]
        public string Code { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Changed { get; set; }

        public string Message { get; private set; }

        public string ErrorMessage { get; private set; }

        public IReadOnlyList<PublicKeyEntry> Keys { get; private set; } = Array.Empty<PublicKeyEntry>();

        public TwoFactorStatus TwoFactor { get; private set; }

        /// <summary>The new secret of a setup that waits for the first code (shown only in the answer of "Set up").</summary>
        public TwoFactorSetup Setup { get; private set; }

        /// <summary>New recovery codes (shown once).</summary>
        public IReadOnlyList<string> RecoveryCodes { get; private set; }

        public IReadOnlyList<ConnectionInfo> Sessions { get; private set; } = Array.Empty<ConnectionInfo>();

        public Guid? CurrentSession => ClientClaims.Session(User);

        public bool AllowsPublicKeys { get; private set; }

        private string Username => User.Identity!.Name;

        private CancellationToken Ct => HttpContext.RequestAborted;

        public async Task<IActionResult> OnGetAsync()
        {
            if (Changed == "password")
                Message = "Your password was changed.";
            return await ShowAsync();
        }

        public Task<IActionResult> OnPostAddKeysAsync() => RunAsync(() =>
        {
            var (added, skipped) = _account.AddPublicKeys(Username, KeysText);
            KeysText = null;
            Message = skipped > 0 ? $"{added} key(s) added, {skipped} you had already." : $"{added} key(s) added.";
            return Task.CompletedTask;
        });

        public Task<IActionResult> OnPostRemoveKeyAsync(string key) => RunAsync(() =>
        {
            Message = _account.RemovePublicKey(Username, key) ? "The key was removed." : "You do not have this key.";
            return Task.CompletedTask;
        });

        public Task<IActionResult> OnPostBeginTotpAsync() => RunAsync(async () =>
        {
            Setup = await _account.BeginTwoFactorSetupAsync(Username, Ct);
        });

        public Task<IActionResult> OnPostConfirmTotpAsync() => RunAsync(async () =>
        {
            RecoveryCodes = await _account.ConfirmTwoFactorSetupAsync(Username, Code, Ct);
            Message = "Two-factor authentication is on. Every login needs a code of the app now.";
        });

        public Task<IActionResult> OnPostRegenerateCodesAsync() => RunAsync(async () =>
        {
            RecoveryCodes = await _account.RegenerateRecoveryCodesAsync(Username, Code, Ct);
        });

        public Task<IActionResult> OnPostDisableTotpAsync() => RunAsync(async () =>
        {
            await _account.DisableTwoFactorAsync(Username, Code, Ct);
            Message = "Two-factor authentication is off.";
        });

        public Task<IActionResult> OnPostEndSessionAsync(Guid id) => RunAsync(async () =>
        {
            if (id == CurrentSession)
                throw new ClientAccountException("This is the current session. Use Log out.");
            Message = await _account.EndSessionAsync(Username, id) ? "The session was closed." : "The session is not open any more.";
        });

        private async Task<IActionResult> RunAsync(Func<Task> action)
        {
            try
            {
                await action();
            }
            catch (ClientAccountException ex)
            {
                ErrorMessage = ex.Message;
            }
            Code = null;
            ModelState.Clear();
            return await ShowAsync();
        }

        private async Task<IActionResult> ShowAsync()
        {
            var user = _account.GetUser(Username);
            if (user == null)
                return Challenge(ClientAuth.Scheme);
            Keys = _account.ListPublicKeys(Username);
            AllowsPublicKeys = (user.AllowedAuthMethods & AuthMethods.PublicKey) != 0;
            TwoFactor = await _account.GetTwoFactorStatusAsync(Username, Ct);
            Sessions = _account.ListSessions(Username);
            return Page();
        }
    }
}
