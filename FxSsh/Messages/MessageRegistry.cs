using System;
using System.Collections.Generic;
using FxSsh.Messages.Connection;
using FxSsh.Messages.UserAuth;

namespace FxSsh.Messages
{
    /// <summary>
    /// Compile-time registry of inbound (client -> server) SSH message numbers
    /// to parameterless factories. Replaces the former runtime reflection scan
    /// (Assembly.GetTypes + GetCustomAttributes + Activator.CreateInstance) so
    /// the library stays NativeAOT/trimming compatible. The [Message] attribute
    /// remains as protocol documentation and is no longer read at runtime.
    ///
    /// Server -> client messages (ServiceAcceptMessage, KeyExchangeXReplyMessage,
    /// FailureMessage, SuccessMessage, PublicKeyOkMessage, ChannelSuccessMessage,
    /// ChannelFailureMessage) are deliberately NOT registered: a server never
    /// receives them, so an inbound packet of those types falls through to
    /// UnknownMessage and gets an SSH_MSG_UNIMPLEMENTED reply, as before.
    ///
    /// Subclasses of a registered base type (KeyExchangeDhInitMessage /
    /// KeyExchangeECDhInitMessage under KeyExchangeXInitMessage, and the
    /// ChannelRequestMessage request types) are materialised later via
    /// Message.LoadFrom&lt;T&gt; using protocol context (negotiated KEX name /
    /// request type string), not by message number.
    /// </summary>
    internal static class MessageRegistry
    {
        private static readonly Dictionary<byte, Func<Message>> _factories = new()
        {
            [DisconnectMessage.MessageNumber] = () => new DisconnectMessage(),
            [ShouldIgnoreMessage.MessageNumber] = () => new ShouldIgnoreMessage(),
            [UnimplementedMessage.MessageNumber] = () => new UnimplementedMessage(),
            [ServiceRequestMessage.MessageNumber] = () => new ServiceRequestMessage(),
            [ExtInfoMessage.MessageNumber] = () => new ExtInfoMessage(),
            [KeyExchangeInitMessage.MessageNumber] = () => new KeyExchangeInitMessage(),
            [NewKeysMessage.MessageNumber] = () => new NewKeysMessage(),
            [KeyExchangeXInitMessage.MessageNumber] = () => new KeyExchangeXInitMessage(),
            [RequestMessage.MessageNumber] = () => new RequestMessage(),
            [GlobalRequestMessage.MessageNumber] = () => new GlobalRequestMessage(),
            [RequestSuccessMessage.MessageNumber] = () => new RequestSuccessMessage(),
            [RequestFailureMessage.MessageNumber] = () => new RequestFailureMessage(),
            [ChannelOpenMessage.MessageNumber] = () => new ChannelOpenMessage(),
            [ChannelOpenConfirmationMessage.MessageNumber] = () => new ChannelOpenConfirmationMessage(),
            [ChannelOpenFailureMessage.MessageNumber] = () => new ChannelOpenFailureMessage(),
            [ChannelWindowAdjustMessage.MessageNumber] = () => new ChannelWindowAdjustMessage(),
            [ChannelDataMessage.MessageNumber] = () => new ChannelDataMessage(),
            [ChannelEofMessage.MessageNumber] = () => new ChannelEofMessage(),
            [ChannelCloseMessage.MessageNumber] = () => new ChannelCloseMessage(),
            [ChannelRequestMessage.MessageNumber] = () => new ChannelRequestMessage(),
        };

        /// <summary>
        /// Create an inbound message instance for <paramref name="typeNumber"/>.
        /// Returns false when the type is not implemented; the caller then
        /// substitutes an UnknownMessage (answered with SSH_MSG_UNIMPLEMENTED).
        /// </summary>
        internal static bool TryCreate(byte typeNumber, out Message message)
        {
            if (_factories.TryGetValue(typeNumber, out var factory))
            {
                message = factory();
                return true;
            }

            message = null;
            return false;
        }
    }
}
