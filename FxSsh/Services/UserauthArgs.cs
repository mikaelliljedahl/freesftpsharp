using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class UserAuthArgs
    {
        public UserAuthArgs(string keyAlgorithm, string fingerprint, byte[] key) : this(AuthType.PublicKey)
        {
            Contract.Requires(keyAlgorithm != null);
            Contract.Requires(fingerprint != null);
            Contract.Requires(key != null);

            KeyAlgorithm = keyAlgorithm;
            Fingerprint = fingerprint;
            Key = key;
        }

        public UserAuthArgs(string username, string password) : this(AuthType.Password)
        {
            Contract.Requires(username != null);
            Contract.Requires(password != null);

            Username = username;
            Password = password;
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
        public AuthType AuthenticationType { get; private set; }

        // Public Key Auth
        public string KeyAlgorithm { get; private set; }
        public string Fingerprint { get; private set; }
        public byte[] Key { get; private set; }
        public bool Result { get; set; }

        // Password Auth
        public string Username { get; private set; }
        public string Password { get; private set; }
    }
}