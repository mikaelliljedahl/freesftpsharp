using System;
using System.Text;

namespace FxSsh.Messages.UserAuth
{
    /// <summary>
    /// Represents an SSH_MSG_USERAUTH_REQUEST using the "keyboard-interactive"
    /// method (RFC 4256 section 3.1). The server answers with
    /// <see cref="InfoRequestMessage"/>s, or directly with success or failure.
    /// </summary>
    public class KeyboardInteractiveRequestMessage : RequestMessage
    {
        /// <summary>
        /// Gets the language tag (deprecated by RFC 4256, usually empty).
        /// </summary>
        public string LanguageTag { get; private set; }

        /// <summary>
        /// Gets the submethods hint of the client (a comma separated list,
        /// usually empty). The server may ignore it.
        /// </summary>
        public string Submethods { get; private set; }

        /// <summary>
        /// Loads the base request fields, verifies the method name and reads
        /// the language tag and the submethods.
        /// </summary>
        /// <exception cref="ArgumentException">The request uses a method name other than "keyboard-interactive".</exception>
        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            if (MethodName != "keyboard-interactive")
                throw new ArgumentException(string.Format("Method name {0} is not valid.", MethodName));

            LanguageTag = reader.ReadString(Encoding.UTF8);
            Submethods = reader.ReadString(Encoding.UTF8);
        }
    }
}
