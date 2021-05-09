using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class PasswordUserAuthArgs : UserAuthArgs
    {
        public PasswordUserAuthArgs(Session session, string username, string password) : base(session, username, password)
        {
            Contract.Requires(username != null);
            Contract.Requires(password != null);

            this.Username = username;
            this.Password = password;
        }

       
    }
}
