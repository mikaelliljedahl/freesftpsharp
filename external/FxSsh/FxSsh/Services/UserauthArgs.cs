using System;
using System.Collections.Generic;
using FxSsh.Messages.UserAuth;

namespace FxSsh.Services
{
    /// <summary>
    /// Payload for <see cref="UserAuthService.UserAuth"/>, raised for every
    /// authentication attempt. Carries the credentials the client submitted;
    /// the host inspects them and sets <see cref="Result"/> to accept or
    /// reject the attempt.
    /// </summary>
    public class UserAuthArgs
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserAuthArgs"/> class
        /// for a "none" authentication request. <see cref="Username"/> is not
        /// populated on this path.
        /// </summary>
        /// <param name="session">The session requesting authentication.</param>
        public UserAuthArgs(Session session)
        {
            AuthMethod = "none";
            Session = session;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserAuthArgs"/> class
        /// for a "publickey" authentication request.
        /// </summary>
        /// <param name="session">The session requesting authentication.</param>
        /// <param name="username">The user name requesting authentication.</param>
        /// <param name="keyAlgorithm">The client's public key algorithm name, e.g. "ssh-rsa".</param>
        /// <param name="fingerprint">The fingerprint of the client's public key, computed by the library.</param>
        /// <param name="key">The client's public key blob as sent on the wire.</param>
        public UserAuthArgs(Session session, string username, string keyAlgorithm, string fingerprint, byte[] key)
        {
            ArgumentNullException.ThrowIfNull(keyAlgorithm);
            ArgumentNullException.ThrowIfNull(fingerprint);
            ArgumentNullException.ThrowIfNull(key);

            AuthMethod = "publickey";
            KeyAlgorithm = keyAlgorithm;
            Fingerprint = fingerprint;
            Key = key;
            Session = session;
            Username = username;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserAuthArgs"/> class
        /// for a "password" authentication request.
        /// </summary>
        /// <param name="session">The session requesting authentication.</param>
        /// <param name="username">The user name requesting authentication.</param>
        /// <param name="password">The password submitted by the client.</param>
        public UserAuthArgs(Session session, string username, string password)
        {
            ArgumentNullException.ThrowIfNull(username);
            ArgumentNullException.ThrowIfNull(password);

            AuthMethod = "password";
            Username = username;
            Password = password;
            Session = session;
        }

        /// <summary>
        /// Creates the args of a "keyboard-interactive" authentication request
        /// (RFC 4256).
        /// </summary>
        /// <param name="session">The session requesting authentication.</param>
        /// <param name="username">The user name requesting authentication.</param>
        /// <param name="submethods">The submethods hint of the client (usually empty).</param>
        public static UserAuthArgs ForKeyboardInteractive(Session session, string username, string submethods)
        {
            ArgumentNullException.ThrowIfNull(username);

            return new UserAuthArgs(session)
            {
                AuthMethod = "keyboard-interactive",
                Username = username,
                Submethods = submethods ?? "",
            };
        }

        /// <summary>
        /// Gets the authentication method of this attempt: "none",
        /// "password", "publickey" or "keyboard-interactive".
        /// </summary>
        public string AuthMethod { get; private set; }

        /// <summary>
        /// Gets the session requesting authentication.
        /// </summary>
        public Session Session { get; private set; }

        /// <summary>
        /// Gets the user name requesting authentication, or null for a
        /// "none" request.
        /// </summary>
        public string Username { get; private set; }

        /// <summary>
        /// Gets the submitted password; only populated for "password"
        /// requests.
        /// </summary>
        public string Password { get; private set; }

        /// <summary>
        /// Gets the client's public key algorithm name; only populated for
        /// "publickey" requests.
        /// </summary>
        public string KeyAlgorithm { get; private set; }

        /// <summary>
        /// Gets the fingerprint of the client's public key; only populated
        /// for "publickey" requests.
        /// </summary>
        public string Fingerprint { get; private set; }

        /// <summary>
        /// Gets the client's public key blob as sent on the wire; only
        /// populated for "publickey" requests.
        /// </summary>
        public byte[] Key { get; private set; }

        /// <summary>
        /// Gets the submethods hint of the client; only populated for
        /// "keyboard-interactive" requests.
        /// </summary>
        public string Submethods { get; private set; }

        /// <summary>
        /// Gets the answers of the client to the last
        /// <see cref="InfoRequest"/>, in the order of the prompts; null for the
        /// "keyboard-interactive" request itself and for the other methods.
        /// Cleared after the handler returns.
        /// </summary>
        public IReadOnlyList<string> Responses { get; internal set; }

        /// <summary>
        /// Gets or sets the prompts that the service sends for a
        /// "keyboard-interactive" attempt (SSH_MSG_USERAUTH_INFO_REQUEST) when
        /// the handler leaves <see cref="Result"/> false. The service raises
        /// <see cref="UserAuthService.UserAuth"/> again with the responses.
        /// Null: no prompt (the attempt fails unless <see cref="Result"/> is
        /// true). Ignored for the other methods.
        /// </summary>
        public KeyboardInteractiveInfoRequest InfoRequest { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the host accepts the
        /// authentication attempt. Defaults to false (reject).
        /// </summary>
        public bool Result { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the accepted attempt is
        /// only one step of a multi-step authentication (RFC 4252 section
        /// 5.1). Used together with <see cref="Result"/> = true: once the
        /// credentials are verified (for "publickey": the signature), the
        /// service raises <see cref="UserAuthService.PartialSucceed"/> and
        /// answers SSH_MSG_USERAUTH_FAILURE with partial success = true
        /// instead of SSH_MSG_USERAUTH_SUCCESS; no service is started.
        /// Defaults to false.
        /// </summary>
        public bool PartialSuccess { get; set; }
    }
}
