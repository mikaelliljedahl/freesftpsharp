using System;
using System.Security.Claims;
using FxSsh.SshServerModule.Security;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Events;

namespace FxSshSftpServer.Security
{
    /// <summary>
    /// The end of an admin login, the same for the password page and the code page (#63): the throttle, the time of the
    /// login, the auth events and the login cookie.
    /// </summary>
    public sealed class AdminLoginFlow
    {
        /// <summary>The <see cref="AuthEvent.Protocol"/> of the admin logins in the audit log.</summary>
        public const string AuditProtocol = "AdminUI";

        private readonly AdminAdministrationService _administration;
        private readonly LoginThrottle _throttle;
        private readonly IEventBus _events;
        private readonly TimeProvider _time;
        private readonly ILogger<AdminLoginFlow> _logger;

        public AdminLoginFlow(AdminAdministrationService administration, LoginThrottle throttle, IEventBus events, TimeProvider time,
            ILogger<AdminLoginFlow> logger)
        {
            _administration = administration;
            _throttle = throttle;
            _events = events;
            _time = time;
            _logger = logger;
        }

        /// <summary>Signs the administrator in and redirects to <paramref name="returnUrl"/> (or the password change).</summary>
        /// <param name="method">The methods of the login for the events, for example "password" or "password,totp".</param>
        public async Task<IActionResult> CompleteAsync(PageModel page, Admin admin, string method, string returnUrl)
        {
            var context = page.HttpContext;
            await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, await RecordSuccessAsync(context, admin, method, null));

            var target = page.Url.IsLocalUrl(returnUrl) ? returnUrl : "/";
            if (admin.MustChangePassword)
                return page.LocalRedirect("/ChangePassword?ReturnUrl=" + Uri.EscapeDataString(target));
            return page.LocalRedirect(target);
        }

        /// <summary>
        /// The success of a login (the throttle, the log, the time of the login, the events) and the principal of the login
        /// cookie. <paramref name="identityProvider"/> is the scheme of an OpenID Connect sign-in (#73): it adds the claim
        /// for the logout at the provider and the <see cref="AuthEventType.IdpLogin"/> event.
        /// </summary>
        public async Task<ClaimsPrincipal> RecordSuccessAsync(HttpContext context, Admin admin, string method, string identityProvider)
        {
            var client = context.Connection.RemoteIpAddress?.ToString();
            _throttle.RecordSuccess(client);
            _logger.LogInformation("Admin {UserName} logged in from {Client} ({Method}).", LogText.Clean(admin.Username), client, method);
            await _administration.RecordLoginAsync(admin, context.RequestAborted);
            await PublishAsync(context, AuthEventType.LoginOk, admin.Username, method, null);

            var principal = AdminClaims.CreatePrincipal(admin);
            if (!string.IsNullOrEmpty(identityProvider))
            {
                ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim(Oidc.OidcClaims.IdentityProviderClaim, identityProvider));
                await PublishAsync(context, AuthEventType.IdpLogin, admin.Username, method, null);
            }
            return principal;
        }

        public Task PublishFailedAsync(HttpContext context, string userName, string method, string reason) =>
            PublishAsync(context, AuthEventType.LoginFailed, userName, method, reason);

        private async Task PublishAsync(HttpContext context, AuthEventType type, string userName, string method, string reason)
        {
            await _events.PublishAsync(new AuthEvent(type)
            {
                Timestamp = _time.GetUtcNow(),
                Username = userName?.Trim(),
                RemoteIp = context.Connection.RemoteIpAddress?.ToString(),
                Protocol = AuditProtocol,
                Method = method,
                Reason = reason,
            }, context.RequestAborted);
        }
    }
}
