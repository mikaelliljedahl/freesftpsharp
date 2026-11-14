using System;
using System.Collections.Generic;
using System.Text;

namespace FxSsh.Messages.UserAuth
{
    /// <summary>
    /// Represents the SSH_MSG_USERAUTH_FAILURE (51) message (RFC 4252
    /// section 5.1). Sent to reject an authentication attempt, or with
    /// partial success = true when the method succeeded but the server needs
    /// more methods. By default it offers the "password,publickey" methods
    /// without partial success.
    /// </summary>
    [Message("SSH_MSG_USERAUTH_FAILURE", MessageNumber)]
    public class FailureMessage : UserAuthServiceMessage
    {
        internal const byte MessageNumber = 51;

        /// <summary>
        /// The method list of a failure when the host sets no other one.
        /// </summary>
        public static readonly IReadOnlyList<string> DefaultAuthenticationsThatCanContinue = ["password", "publickey"];

        /// <summary>
        /// Initializes a failure with the default method list
        /// ("password,publickey") and partial success = false.
        /// </summary>
        public FailureMessage()
            : this(DefaultAuthenticationsThatCanContinue, false)
        {
        }

        /// <summary>
        /// Initializes a failure with the given method list and partial
        /// success flag.
        /// </summary>
        /// <param name="authenticationsThatCanContinue">The methods that may continue the authentication.</param>
        /// <param name="partialSuccess">True when the request succeeded but more methods are needed.</param>
        public FailureMessage(IReadOnlyList<string> authenticationsThatCanContinue, bool partialSuccess)
        {
            ArgumentNullException.ThrowIfNull(authenticationsThatCanContinue);
            AuthenticationsThatCanContinue = authenticationsThatCanContinue;
            PartialSuccess = partialSuccess;
        }

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_USERAUTH_FAILURE (51).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Gets the methods that may continue the authentication (the
        /// name-list of the message).
        /// </summary>
        public IReadOnlyList<string> AuthenticationsThatCanContinue { get; }

        /// <summary>
        /// Gets a value indicating whether the request succeeded but more
        /// methods are needed (RFC 4252 section 5.1 "partial success").
        /// </summary>
        public bool PartialSuccess { get; }

        /// <summary>
        /// Writes the name-list of acceptable methods and the partial
        /// success flag to the payload.
        /// </summary>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.WriteBinary(Encoding.ASCII.GetBytes(string.Join(",", AuthenticationsThatCanContinue)));
            writer.Write(PartialSuccess);
        }
    }
}
