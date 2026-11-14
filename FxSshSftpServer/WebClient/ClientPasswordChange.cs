using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The password change of the signed-in web client user: the throttle for wrong current passwords, the change
    /// (<see cref="ClientAccountService.ChangePassword"/>), a new login cookie with the new stamp for this session (also
    /// without the forced change), and the end of the other browser sessions of the user.
    /// </summary>
    public sealed class ClientPasswordChange
    {
        private readonly ClientAccountService _account;
        private readonly ClientSessions _sessions;
        private readonly ClientLoginThrottle _throttle;

        public ClientPasswordChange(ClientAccountService account, ClientSessions sessions, ClientLoginThrottle throttle)
        {
            _account = account;
            _sessions = sessions;
            _throttle = throttle;
        }

        /// <summary>Changes the password; returns an error text for the user, or null.</summary>
        public async Task<string> ChangeAsync(HttpContext context, string currentPassword, string newPassword, string repeatPassword)
        {
            var client = context.Connection.RemoteIpAddress?.ToString();
            if (_throttle.Throttle.IsLockedOut(client))
                return Pages.Client.LoginModel.LockedOutMessage;
            if (ClientClaims.Session(context.User) is not { } session)
                return "You are not logged in.";

            SshServer.Interfaces.User user;
            try
            {
                user = _account.ChangePassword(context.User.Identity!.Name, currentPassword, newPassword, repeatPassword);
            }
            catch (ClientAccountException ex)
            {
                if (ex.Message == ClientAccountService.WrongPasswordMessage)
                    _throttle.Throttle.RecordFailure(client);
                return ex.Message;
            }

            _sessions.EndOthers(user.Username, session);
            await context.SignInAsync(ClientAuth.Scheme, ClientClaims.CreatePrincipal(user, session, mustChangePassword: false));
            return null;
        }
    }
}
