using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Net;

namespace FxSshSftpServer.WebClient
{
    /// <summary>The login throttle of the web client: its own counter, apart from the admin login.</summary>
    public sealed class ClientLoginThrottle
    {
        public ClientLoginThrottle(SshServer.Administration.LoginThrottle throttle) => Throttle = throttle;

        public SshServer.Administration.LoginThrottle Throttle { get; }
    }

    /// <summary>
    /// The end of a web client login, the same for the password page and the code page: the session in the connection
    /// registry (with the session limit), the throttle, the time of the login, the auth events (protocol HTTP) and the
    /// login cookie.
    /// </summary>
    public sealed class ClientLoginFlow
    {
        public const string TooManySessionsMessage = "You have the maximum number of sessions open. Log out elsewhere first.";

        private readonly ClientSessions _sessions;
        private readonly ClientLoginThrottle _throttle;
        private readonly ISettingsRepository _repository;
        private readonly IEventBus _events;
        private readonly TimeProvider _time;
        private readonly ILogger<ClientLoginFlow> _logger;

        public ClientLoginFlow(ClientSessions sessions, ClientLoginThrottle throttle, ISettingsRepository repository, IEventBus events,
            TimeProvider time, ILogger<ClientLoginFlow> logger)
        {
            _sessions = sessions;
            _throttle = throttle;
            _repository = repository;
            _events = events;
            _time = time;
            _logger = logger;
        }

        /// <summary>
        /// Signs the user in and redirects (to the password change when the password expired). Null when the session
        /// limit refused the login at the last moment: the page shows <see cref="TooManySessionsMessage"/>.
        /// </summary>
        public async Task<IActionResult> CompleteAsync(PageModel page, User user, string method, bool passwordExpired, string returnUrl)
        {
            var context = page.HttpContext;
            var principal = await StartAsync(context, user, method, passwordExpired, null);
            if (principal == null)
                return null;

            await context.SignInAsync(ClientAuth.Scheme, principal);
            if (passwordExpired)
                return page.LocalRedirect("/client/changepassword");
            return page.LocalRedirect(IsClientUrl(page, returnUrl) ? returnUrl : ClientAuth.BasePath);
        }

        /// <summary>
        /// Starts the session (with the session limit), records the login (throttle, log, time, events) and returns the
        /// principal of the login cookie; null when the session limit refused the login. <paramref name="identityProvider"/>
        /// is the scheme of an OpenID Connect sign-in (#73): it adds the claim for the logout at the provider and the
        /// <see cref="AuthEventType.IdpLogin"/> event.
        /// </summary>
        public async Task<System.Security.Claims.ClaimsPrincipal> StartAsync(HttpContext context, User user, string method, bool passwordExpired,
            string identityProvider)
        {
            var client = context.Connection.RemoteIpAddress;
            var session = _sessions.Start(user, method, client, context.Connection.RemotePort);
            if (session is not { } id)
            {
                await PublishAsync(context, AuthEventType.LoginFailed, user.Username, method, SshServer.Interfaces.Users.UserLoginRules.SessionLimitReason(user.MaxSessions), null);
                return null;
            }

            _throttle.Throttle.RecordSuccess(client?.ToString());
            _logger.LogInformation("User {Username} logged in to the web client from {Client} ({Method}).", FxSsh.SshServerModule.Security.LogText.Clean(user.Username), client, method);
            RecordLoginTime(user.Username);
            await PublishAsync(context, AuthEventType.LoginOk, user.Username, method, null, id);
            if (!string.IsNullOrEmpty(identityProvider))
                await PublishAsync(context, AuthEventType.IdpLogin, user.Username, method, null, id);
            return ClientClaims.CreatePrincipal(user, id, passwordExpired, identityProvider);
        }

        public Task PublishFailedAsync(HttpContext context, string userName, string method, string reason) =>
            PublishAsync(context, AuthEventType.LoginFailed, userName, method, reason, null);

        /// <summary>True for a local URL in the client area (the target after the login).</summary>
        public static bool IsClientUrl(PageModel page, string url) =>
            !string.IsNullOrEmpty(url) && page.Url.IsLocalUrl(url)
            && (url.Equals(ClientAuth.BasePath, StringComparison.OrdinalIgnoreCase) || url.StartsWith(ClientAuth.BasePath + "/", StringComparison.OrdinalIgnoreCase)
                || url.StartsWith(ClientAuth.BasePath + "?", StringComparison.OrdinalIgnoreCase));

        private void RecordLoginTime(string username)
        {
            try
            {
                var stored = _repository.GetUser(username);
                if (stored == null)
                    return;
                stored.LastLoginAt = _time.GetUtcNow().UtcDateTime;
                if (!_repository.UpdateUser(stored))
                    _logger.LogWarning("Could not save the last login time of user {Username}.", username);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not save the last login time of user {Username}.", username);
            }
        }

        private async Task PublishAsync(HttpContext context, AuthEventType type, string userName, string method, string reason, Guid? session)
        {
            var ip = context.Connection.RemoteIpAddress;
            await _events.PublishAsync(new AuthEvent(type)
            {
                Timestamp = _time.GetUtcNow(),
                Username = userName?.Trim(),
                RemoteIp = ip == null ? null : CidrNotation.Normalize(ip).ToString(),
                Protocol = ClientAuth.Protocol,
                Method = method,
                Reason = reason,
                SessionId = session?.ToString(),
            }, context.RequestAborted);
        }
    }
}
