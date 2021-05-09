using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    
    public abstract class UserAuthArgs
    {
        public UserAuthArgs(Session session, string username, string keyAlgorithm, string fingerprint, byte[] key) : this(AuthType.PublicKey)
        {
            Contract.Requires(username != null);
            Contract.Requires(keyAlgorithm != null);
            Contract.Requires(fingerprint != null);
            Contract.Requires(key != null);


            Username = username;
            KeyAlgorithm = keyAlgorithm;
            Fingerprint = fingerprint;
            Key = key;
            Session = session;
        }

        public UserAuthArgs(Session session, string username, string password) : this(AuthType.Password)
        {
            Contract.Requires(username != null);
            Contract.Requires(password != null);

            Username = username;
            Password = password;
            Session = session;
        }

        protected UserAuthArgs(AuthType authType)
        {
            AuthenticationType = authType;
        }

        public enum AuthType
        {
            PublicKey,
            Password
        }

        // Info
        public AuthType AuthenticationType { get; set; }

        public Session Session { get; set; }

        public string Username { get; set; }

        // Public Key Auth
        public string KeyAlgorithm { get; set; }
        public string Fingerprint { get; set; }
        public byte[] Key { get; set; }
        public bool Result { get; set; }


        // Password Auth        
        public string Password { get; set; }
    }
}
    