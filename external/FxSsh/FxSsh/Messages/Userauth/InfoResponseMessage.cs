using System;
using System.Collections.Generic;
using System.Text;

namespace FxSsh.Messages.UserAuth
{
    /// <summary>
    /// Represents the SSH_MSG_USERAUTH_INFO_RESPONSE (61) message (RFC 4256
    /// section 3.4): the answers of the client to the prompts of the last
    /// <see cref="InfoRequestMessage"/>, in the same order.
    /// </summary>
    [Message("SSH_MSG_USERAUTH_INFO_RESPONSE", MessageNumber)]
    public class InfoResponseMessage : UserAuthServiceMessage
    {
        internal const byte MessageNumber = 61;

        /// <summary>
        /// The most responses that are read. A server asks only a few
        /// questions; a longer list is a protocol error.
        /// </summary>
        public const int MaximumResponses = 32;

        /// <summary>
        /// Gets the responses of the client (UTF-8 text).
        /// </summary>
        public IReadOnlyList<string> Responses { get; private set; } = [];

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_USERAUTH_INFO_RESPONSE (61).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Reads the number of responses and the responses.
        /// </summary>
        /// <exception cref="ArgumentException">More than <see cref="MaximumResponses"/> responses.</exception>
        protected override void OnLoad(SshDataReader reader)
        {
            var count = reader.ReadUInt32();
            if (count > MaximumResponses)
                throw new ArgumentException(string.Format("Too many keyboard-interactive responses: {0}.", count));

            var responses = new string[count];
            for (var i = 0; i < responses.Length; i++)
                responses[i] = reader.ReadString(Encoding.UTF8);
            Responses = responses;
        }
    }
}
