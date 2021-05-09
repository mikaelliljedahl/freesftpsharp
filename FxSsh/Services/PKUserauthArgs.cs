using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class PKUserAuthArgs : UserAuthArgs
    {
        public PKUserAuthArgs(Session session, string username, string keyAlgorithm, string fingerprint, byte[] key) : base(session, username, keyAlgorithm, fingerprint, key)
        {
            Contract.Requires(username != null);
            Contract.Requires(keyAlgorithm != null);
            Contract.Requires(fingerprint != null);
            Contract.Requires(key != null);

            KeyAlgorithm = keyAlgorithm;
            Fingerprint = fingerprint;
            Key = key;
            Username = username;
        }
    }
}