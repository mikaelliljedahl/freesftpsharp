using System;
using System.Collections.Generic;
using FxSsh.Logging;
using FxSsh.Messages;
using FxSsh.Messages.UserAuth;

namespace FxSsh.Services
{
    /// <summary>
    /// Implements the "ssh-userauth" service (RFC 4252): validates "password",
    /// "publickey", "keyboard-interactive" (RFC 4256) and optionally "none"
    /// authentication requests by delegating
    /// the accept/reject decision to the <see cref="UserAuth"/> event, and
    /// registers the service the client asked to start (usually
    /// "ssh-connection") once authentication succeeds.
    /// </summary>
    public class UserAuthService : SshService
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserAuthService"/> class.
        /// </summary>
        /// <param name="session">The session that instantiated the service for SSH_MSG_SERVICE_REQUEST "ssh-userauth".</param>
        public UserAuthService(Session session)
            : base(session)
        {
        }

        /// <summary>
        /// Gets or sets a value indicating whether the "none" authentication
        /// method (RFC 4252 section 5) is accepted. Disabled by default;
        /// when enabled, the <see cref="UserAuth"/> handler still decides
        /// whether the request succeeds.
        /// </summary>
        public bool EnableNoneAuth { get; set; } = false;

        /// <summary>
        /// Raised for every authentication attempt with the credentials the
        /// client presented ("password", "publickey", "keyboard-interactive"
        /// or "none"). The handler must set <see cref="UserAuthArgs.Result"/>
        /// to true to accept; with no handler subscribed, every attempt is
        /// rejected.
        /// <para>
        /// For "keyboard-interactive" (RFC 4256) the event is raised for the
        /// request (<see cref="UserAuthArgs.Responses"/> is null) and again,
        /// with the same args, for each SSH_MSG_USERAUTH_INFO_RESPONSE. To ask
        /// the client, the handler sets <see cref="UserAuthArgs.InfoRequest"/>
        /// and leaves <see cref="UserAuthArgs.Result"/> false; the service sends
        /// SSH_MSG_USERAUTH_INFO_REQUEST and waits for the answers.
        /// </para>
        /// </summary>
        public event EventHandler<UserAuthArgs> UserAuth;

        /// <summary>
        /// Occurs after authentication succeeds, carrying the service name the
        /// client asked to start (usually "ssh-connection").
        /// </summary>
        public event EventHandler<string> Succeed;

        /// <summary>
        /// Occurs when an attempt that the <see cref="UserAuth"/> handler
        /// accepted with <see cref="UserAuthArgs.PartialSuccess"/> = true is
        /// verified (for "publickey": after the signature check). The service
        /// then answers SSH_MSG_USERAUTH_FAILURE with partial success = true
        /// and the current <see cref="AuthenticationsThatCanContinue"/>, which
        /// the handler may change here.
        /// </summary>
        public event EventHandler<UserAuthArgs> PartialSucceed;

        /// <summary>
        /// Gets or sets the methods that SSH_MSG_USERAUTH_FAILURE offers
        /// (RFC 4252 section 5.1). Defaults to "password,publickey"; a host
        /// with multi-step authentication sets the remaining methods after a
        /// partial success.
        /// </summary>
        public IReadOnlyList<string> AuthenticationsThatCanContinue { get; set; } = FailureMessage.DefaultAuthenticationsThatCanContinue;

        /// <summary>
        /// Implements the base teardown hook; the user authentication service
        /// holds no resources, so this is a no-op.
        /// </summary>
        protected internal override void CloseService()
        {
        }

        /// <summary>
        /// The keyboard-interactive exchange that waits for an
        /// SSH_MSG_USERAUTH_INFO_RESPONSE, or null.
        /// </summary>
        private PendingKeyboardInteractive _pendingKeyboardInteractive;

        private sealed record PendingKeyboardInteractive(UserAuthArgs Args, string Username, string ServiceName, int PromptCount);

        internal void HandleMessageCore(UserAuthServiceMessage message)
        {
            ArgumentNullException.ThrowIfNull(message);

            // RFC 4256 section 3.4: a new request ends the keyboard-interactive
            // exchange that waits for responses.
            if (message is RequestMessage)
                _pendingKeyboardInteractive = null;

            // Compile-time dispatch replacing the former (dynamic) binder.
            // Concrete RequestMessage subclasses are matched before the
            // RequestMessage base, mirroring the old most-specific-overload
            // dynamic binding.
            switch (message)
            {
                case NoneRequestMessage m: HandleMessage(m); break;
                case PasswordRequestMessage m: HandleMessage(m); break;
                case PublicKeyRequestMessage m: HandleMessage(m); break;
                case KeyboardInteractiveRequestMessage m: HandleMessage(m); break;
                case RequestMessage m: HandleMessage(m); break;
                case InfoResponseMessage m: HandleMessage(m); break;
            }
        }

        private void HandleMessage(RequestMessage message)
        {
            var username = string.IsNullOrEmpty(message.Username) ? "?" : message.Username;
            Log.Info($"Auth attempt: method={message.MethodName} user={username}.");
            switch (message.MethodName)
            {
                case "none" when EnableNoneAuth:
                    var noneMsg = Message.LoadFrom<NoneRequestMessage>(message);
                    HandleMessage(noneMsg);
                    break;
                case "publickey":
                    var keyMsg = Message.LoadFrom<PublicKeyRequestMessage>(message);
                    HandleMessage(keyMsg);
                    break;
                case "password":
                    var pswdMsg = Message.LoadFrom<PasswordRequestMessage>(message);
                    HandleMessage(pswdMsg);
                    break;
                case "keyboard-interactive":
                    var kbdMsg = Message.LoadFrom<KeyboardInteractiveRequestMessage>(message);
                    HandleMessage(kbdMsg);
                    break;
                case "hostbased":
                default:
                    Log.Debug($"Unsupported auth method: {message.MethodName}.");
                    SendFailure();
                    break;
            }
        }

        private void HandleMessage(NoneRequestMessage message)
        {
            var verifed = false;
            var args = new UserAuthArgs(_session);
            if (UserAuth != null)
            {
                UserAuth(this, args);
                verifed = args.Result;
            }
            if (verifed && args.PartialSuccess)
            {
                SendPartialSuccess("none", message.Username, args);
                return;
            }
            if (verifed)
            {
                Log.Info($"Auth succeeded: none, user {message.Username}.");
                _session.RegisterService(message.ServiceName, args);
                Succeed?.Invoke(this, message.ServiceName);
                _session.SendMessage(new SuccessMessage());
                return;
            }
            else
            {
                Log.Warn($"Auth failed: none, user {message.Username}.");
                SendFailure();
            }
        }

        private void HandleMessage(PasswordRequestMessage message)
        {
            var verifed = false;

            var args = new UserAuthArgs(_session, message.Username, message.Password);
            if (UserAuth != null)
            {
                UserAuth(this, args);
                verifed = args.Result;
            }

            if (verifed && args.PartialSuccess)
            {
                SendPartialSuccess("password", message.Username, args);
                return;
            }

            if (verifed)
            {
                Log.Info($"Auth succeeded: password, user {message.Username}.");
                _session.RegisterService(message.ServiceName, args);

                Succeed?.Invoke(this, message.ServiceName);

                _session.SendMessage(new SuccessMessage());
                return;
            }
            else
            {
                Log.Warn($"Auth failed: password, user {message.Username}.");
                SendFailure();
            }
        }

        private void HandleMessage(PublicKeyRequestMessage message)
        {
            if (_session._publicKeyAlgorithms.ContainsKey(message.KeyAlgorithmName))
            {
                var verifed = false;

                var keyAlg = _session._publicKeyAlgorithms[message.KeyAlgorithmName](null);
                keyAlg.LoadKeyAndCertificatesData(message.PublicKey);

                var args = new UserAuthArgs(base._session, message.Username, message.KeyAlgorithmName, keyAlg.GetFingerprint(), message.PublicKey);
                UserAuth?.Invoke(this, args);
                verifed = args.Result;

                Log.Info($"Public key auth: user={message.Username} alg={message.KeyAlgorithmName} fp={args.Fingerprint}.");

                if (!verifed)
                {
                    Log.Warn($"Public key auth rejected by host policy: user {message.Username}.");
                    SendFailure();
                    return;
                }

                if (!message.HasSignature)
                {
                    Log.Debug("Public key accepted, awaiting signature.");
                    _session.SendMessage(new PublicKeyOkMessage { KeyAlgorithmName = message.KeyAlgorithmName, PublicKey = message.PublicKey });
                    return;
                }

                var sig = keyAlg.GetSignature(message.Signature);

                // A signed request can only be verified against an established
                // session id; one arriving before key exchange is malformed
                // and is rejected instead of dereferencing a null id.
                if (_session.SessionId == null)
                {
                    Log.Warn($"Public key signature received before key exchange: user {message.Username}.");
                    SendFailure();
                    return;
                }

                var bytes = new SshDataWriter(4 + _session.SessionId.Length + message.PayloadWithoutSignature.Length)
                    .WriteBinary(_session.SessionId)
                    .WriteBytes(message.PayloadWithoutSignature)
                    .ToByteArray();

                verifed = keyAlg.VerifyData(bytes, sig);

                if (!verifed)
                {
                    Log.Warn($"Public key signature verification failed: user {message.Username}.");
                    SendFailure();
                    return;
                }

                if (args.PartialSuccess)
                {
                    SendPartialSuccess("publickey", message.Username, args);
                    return;
                }

                Log.Info($"Auth succeeded: publickey, user {message.Username}.");
                _session.RegisterService(message.ServiceName, args);
                Succeed?.Invoke(this, message.ServiceName);
                _session.SendMessage(new SuccessMessage());
            }
            else
            {
                Log.Warn($"Unsupported key algorithm: {message.KeyAlgorithmName}.");
                SendFailure();
            }
        }

        private void HandleMessage(KeyboardInteractiveRequestMessage message)
        {
            var args = UserAuthArgs.ForKeyboardInteractive(_session, message.Username, message.Submethods);
            UserAuth?.Invoke(this, args);
            CompleteKeyboardInteractive(args, message.Username, message.ServiceName);
        }

        private void HandleMessage(InfoResponseMessage message)
        {
            var pending = _pendingKeyboardInteractive;
            _pendingKeyboardInteractive = null;
            if (pending == null)
            {
                // RFC 4256 section 3.4 does not allow a response without a
                // request; ignore it, the client gets no answer to it.
                Log.Warn("Keyboard-interactive response without a pending request; ignored.");
                return;
            }

            if (message.Responses.Count != pending.PromptCount)
            {
                Log.Warn($"Auth failed: keyboard-interactive, user {pending.Username}: {message.Responses.Count} responses for {pending.PromptCount} prompts.");
                SendFailure();
                return;
            }

            var args = pending.Args;
            args.Result = false;
            args.PartialSuccess = false;
            args.InfoRequest = null;
            args.Responses = message.Responses;
            try
            {
                UserAuth?.Invoke(this, args);
            }
            finally
            {
                // The responses can be secrets; the args stay attached to the
                // session after the login.
                args.Responses = [];
            }
            CompleteKeyboardInteractive(args, pending.Username, pending.ServiceName);
        }

        /// <summary>
        /// Answers a keyboard-interactive request or response after the
        /// <see cref="UserAuth"/> handler: another round of prompts, success,
        /// partial success or failure.
        /// </summary>
        private void CompleteKeyboardInteractive(UserAuthArgs args, string username, string serviceName)
        {
            if (!args.Result && args.InfoRequest is { } request)
            {
                _pendingKeyboardInteractive = new PendingKeyboardInteractive(args, username, serviceName, request.Prompts.Count);
                Log.Debug($"Keyboard-interactive: {request.Prompts.Count} prompt(s) sent, user {username}.");
                _session.SendMessage(new InfoRequestMessage(request));
                return;
            }

            if (args.Result && args.PartialSuccess)
            {
                SendPartialSuccess("keyboard-interactive", username, args);
                return;
            }

            if (args.Result)
            {
                Log.Info($"Auth succeeded: keyboard-interactive, user {username}.");
                _session.RegisterService(serviceName, args);
                Succeed?.Invoke(this, serviceName);
                _session.SendMessage(new SuccessMessage());
                return;
            }

            Log.Warn($"Auth failed: keyboard-interactive, user {username}.");
            SendFailure();
        }

        private void SendFailure()
        {
            _session.SendMessage(new FailureMessage(AuthenticationsThatCanContinue, false));
        }

        private void SendPartialSuccess(string method, string username, UserAuthArgs args)
        {
            Log.Info($"Auth partially succeeded: {method}, user {username}; more methods are needed.");
            PartialSucceed?.Invoke(this, args);
            _session.SendMessage(new FailureMessage(AuthenticationsThatCanContinue, true));
        }
    }
}
