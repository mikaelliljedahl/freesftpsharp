using System;
using System.Collections.Generic;
using System.Text;

namespace FxSsh.Messages.UserAuth
{
    /// <summary>
    /// Represents the SSH_MSG_USERAUTH_INFO_REQUEST (60) message (RFC 4256
    /// section 3.2): the prompts of a "keyboard-interactive" round. It has the
    /// same number as <see cref="PublicKeyOkMessage"/>; the method of the
    /// request decides which one the server sends.
    /// </summary>
    [Message("SSH_MSG_USERAUTH_INFO_REQUEST", MessageNumber)]
    public class InfoRequestMessage : UserAuthServiceMessage
    {
        internal const byte MessageNumber = 60;

        /// <summary>
        /// Initializes the message from the prompts of the host.
        /// </summary>
        /// <param name="request">The name, instruction and prompts of the round.</param>
        public InfoRequestMessage(KeyboardInteractiveInfoRequest request)
        {
            ArgumentNullException.ThrowIfNull(request);
            Request = request;
        }

        /// <summary>
        /// Gets the name, instruction and prompts of the round.
        /// </summary>
        public KeyboardInteractiveInfoRequest Request { get; }

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_USERAUTH_INFO_REQUEST (60).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Writes the name, the instruction, an empty language tag and the
        /// prompts with their echo flags.
        /// </summary>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write(Request.Name ?? "", Encoding.UTF8);
            writer.Write(Request.Instruction ?? "", Encoding.UTF8);
            writer.Write("", Encoding.ASCII); // language tag (deprecated)
            writer.Write((uint)Request.Prompts.Count);
            foreach (var prompt in Request.Prompts)
            {
                writer.Write(prompt.Text, Encoding.UTF8);
                writer.Write(prompt.Echo);
            }
        }
    }

    /// <summary>
    /// One prompt of a "keyboard-interactive" round (RFC 4256 section 3.2).
    /// </summary>
    /// <param name="Text">The prompt text, for example "Verification code: ".</param>
    /// <param name="Echo">True when the client may show what the user types.</param>
    public sealed record KeyboardInteractivePrompt(string Text, bool Echo);

    /// <summary>
    /// The content of one SSH_MSG_USERAUTH_INFO_REQUEST: a name and an
    /// instruction for the user (both may be empty) and the prompts.
    /// </summary>
    public sealed class KeyboardInteractiveInfoRequest
    {
        /// <summary>
        /// Initializes a round with the given texts and prompts.
        /// </summary>
        /// <param name="name">The name of the round (may be empty).</param>
        /// <param name="instruction">The instruction for the user (may be empty).</param>
        /// <param name="prompts">The prompts; zero prompts is allowed by RFC 4256.</param>
        public KeyboardInteractiveInfoRequest(string name, string instruction, IReadOnlyList<KeyboardInteractivePrompt> prompts)
        {
            ArgumentNullException.ThrowIfNull(prompts);
            Name = name ?? "";
            Instruction = instruction ?? "";
            Prompts = prompts;
        }

        /// <summary>Gets the name of the round.</summary>
        public string Name { get; }

        /// <summary>Gets the instruction for the user.</summary>
        public string Instruction { get; }

        /// <summary>Gets the prompts, in order.</summary>
        public IReadOnlyList<KeyboardInteractivePrompt> Prompts { get; }
    }
}
