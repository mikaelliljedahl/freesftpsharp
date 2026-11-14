using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FxSsh;
using FxSsh.Algorithms;
using FxSsh.Messages;
using FxSsh.Messages.UserAuth;
using FxSsh.Services;
using FxSsh.Tests.Messages;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Services
{
    /// <summary>
    /// Drives UserAuthService's auth dispatch (friend assembly) with parsed
    /// SSH_MSG_USERAUTH_REQUEST payloads and observes accept/reject via the
    /// ServiceRegistered event (fired only on success).
    /// </summary>
    [TestClass]
    public sealed class UserAuthServiceTests
    {
        private Socket _clientSocket = null!;
        private Socket _serverSocket = null!;
        private Session _session = null!;
        private readonly System.Threading.CancellationTokenSource _sendPumpCancellation = new();
        private Task? _sendPump;

        [TestInitialize]
        public void CreateSessionOverSocketPair()
        {
            using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            listener.Listen(1);

            _clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _clientSocket.Connect(listener.LocalEndPoint!);
            _serverSocket = listener.Accept();

            _session = new Session(_serverSocket, new Dictionary<string, string>(), "SSH-2.0-FxSsh-Test");
        }

        [TestCleanup]
        public void DisposeSockets()
        {
            _sendPumpCancellation.Cancel();
            _clientSocket.Dispose();
            _serverSocket.Dispose();
        }

        private static RequestMessage LoadRequest(params Action<SshDataWriter>[] fields)
        {
            var writer = TestMessages.Payload(RequestMessage.MessageNumber)
                .Write(UserAuthServiceTests.Username, Encoding.UTF8)
                .Write("ssh-connection", Encoding.ASCII);
            foreach (var field in fields)
                field(writer);
            var request = new RequestMessage();
            request.Load(writer.ToByteArray());
            return request;
        }

        private static RequestMessage NoneRequest() => LoadRequest(w => w.Write("none", Encoding.ASCII));

        private static RequestMessage PasswordRequest(string password) =>
            LoadRequest(
                w => w.Write("password", Encoding.ASCII),
                w => w.Write(false),
                w => w.Write(password, Encoding.ASCII));

        private static RequestMessage PublicKeyRequest(string algorithm, byte[] keyBlob, bool hasSignature, byte[]? signature)
        {
            return LoadRequest(
                w => w.Write("publickey", Encoding.ASCII),
                w => w.Write(hasSignature),
                w => w.Write(algorithm, Encoding.ASCII),
                w => w.WriteBinary(keyBlob),
                w => { if (signature != null) w.WriteBinary(signature); });
        }

        private const string Username = "unit-tester";

        [TestMethod]
        public async Task None_auth_registers_the_connection_service_when_approved()
        {
            var service = new UserAuthService(_session);
            service.EnableNoneAuth = true;

            // The none-flow UserAuthArgs carries no username; approval is
            // purely the host's policy decision.
            service.UserAuth += (_, e) => e.Result = true;

            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(NoneRequest());

            var svc = await registered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.IsInstanceOfType(svc, typeof(ConnectionService));
        }

        [TestMethod]
        public async Task None_auth_is_rejected_when_the_handler_declines()
        {
            var service = new UserAuthService(_session);
            service.EnableNoneAuth = true;
            service.UserAuth += (_, e) => e.Result = false;

            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(NoneRequest());

            await Assert.ThrowsExactlyAsync<TimeoutException>(
                () => registered.Task.WaitAsync(TimeSpan.FromMilliseconds(400)));
        }

        [TestMethod]
        public async Task None_auth_is_rejected_when_not_enabled()
        {
            var service = new UserAuthService(_session);
            Assert.IsFalse(service.EnableNoneAuth);

            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(NoneRequest());

            await Assert.ThrowsExactlyAsync<TimeoutException>(
                () => registered.Task.WaitAsync(TimeSpan.FromMilliseconds(400)));
        }

        [TestMethod]
        public async Task Password_auth_registers_on_match_and_rejects_on_mismatch()
        {
            var service = new UserAuthService(_session);
            var attempts = new List<UserAuthArgs>();
            service.UserAuth += (_, e) =>
            {
                attempts.Add(e);
                e.Result = e.Password == "right-password";
            };

            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(PasswordRequest("wrong-password"));
            await Task.Delay(300);
            Assert.AreEqual(1, attempts.Count);
            Assert.AreEqual("password", attempts[0].AuthMethod);
            Assert.AreEqual("wrong-password", attempts[0].Password);
            Assert.IsFalse(registered.Task.IsCompleted);

            service.HandleMessageCore(PasswordRequest("right-password"));
            var svc = await registered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.IsInstanceOfType(svc, typeof(ConnectionService));
        }

        [TestMethod]
        public async Task PublicKey_auth_reports_fingerprint_and_supports_policy_accept()
        {
            var service = new UserAuthService(_session);
            var attempts = new List<UserAuthArgs>();
            service.UserAuth += (_, e) =>
            {
                attempts.Add(e);
                e.Result = true;
            };

            var pem = KeyGenerator.GenerateECDsaKeyPem("nistp256");
            var blob = new EcdsaKey("nistp256", pem).CreateKeyAndCertificatesData();

            // Two-phase: first request carries no signature; the server answers
            // PublicKeyOk (sent to the peer) without registering the service yet.
            service.HandleMessageCore(PublicKeyRequest("ecdsa-sha2-nistp256", blob, hasSignature: false, signature: null));

            await Task.Delay(300);
            Assert.AreEqual(1, attempts.Count);
            Assert.AreEqual("publickey", attempts[0].AuthMethod);
            Assert.AreEqual("ecdsa-sha2-nistp256", attempts[0].KeyAlgorithm);
            Assert.IsFalse(string.IsNullOrEmpty(attempts[0].Fingerprint));
            CollectionAssert.AreEqual(blob, attempts[0].Key);
        }

        [TestMethod]
        public async Task PublicKey_auth_with_invalid_signature_is_rejected()
        {
            var service = new UserAuthService(_session);
            service.UserAuth += (_, e) => e.Result = true;

            var pem = KeyGenerator.GenerateECDsaKeyPem("nistp256");
            var key = new EcdsaKey("nistp256", pem);
            var blob = key.CreateKeyAndCertificatesData();

            // Structurally valid SSH signature blob, but signed over different
            // data - the library must verify and reject without throwing.
            var wrongSignature = key.CreateSignatureData("other payload"u8.ToArray());

            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(PublicKeyRequest(
                "ecdsa-sha2-nistp256", blob, hasSignature: true, signature: wrongSignature));

            await Assert.ThrowsExactlyAsync<TimeoutException>(
                () => registered.Task.WaitAsync(TimeSpan.FromMilliseconds(400)));
        }

        [TestMethod]
        public async Task PublicKey_auth_with_unknown_algorithm_is_rejected()
        {
            var service = new UserAuthService(_session);
            service.UserAuth += (_, e) => e.Result = true;

            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(PublicKeyRequest(
                "ssh-dss", new byte[] { 0x00 }, hasSignature: false, signature: null));

            await Task.Delay(300);
            Assert.IsFalse(registered.Task.IsCompleted);
        }

        /// <summary>
        /// Reads one SSH binary packet that the session sent to the peer
        /// (no key exchange yet, so it is not encrypted) and returns its payload.
        /// </summary>
        private byte[] ReceivePayload()
        {
            if (_sendPump == null)
            {
                // The session is not started, so its send pump does not run: start only the pump.
                var pump = typeof(Session).GetMethod("ProcessSendChannelAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;
                _sendPump = (Task)pump.Invoke(_session, new object[] { _sendPumpCancellation.Token })!;
            }
            _clientSocket.ReceiveTimeout = 5000;
            var header = ReceiveExactly(5);
            var length = (int)BinaryPrimitives.ReadUInt32BigEndian(header);
            var padding = header[4];
            var rest = ReceiveExactly(length - 1);
            return rest[..(rest.Length - padding)];
        }

        private byte[] ReceiveExactly(int count)
        {
            var buffer = new byte[count];
            var read = 0;
            while (read < count)
            {
                var n = _clientSocket.Receive(buffer, read, count - read, SocketFlags.None);
                if (n == 0)
                    throw new InvalidOperationException("The session closed the socket.");
                read += n;
            }
            return buffer;
        }

        private static (string Methods, bool PartialSuccess) ReadFailure(byte[] payload)
        {
            var reader = new SshDataReader(payload);
            Assert.AreEqual(FailureMessage.MessageNumber, reader.ReadByte());
            return (reader.ReadString(Encoding.ASCII), reader.ReadBoolean());
        }

        [TestMethod]
        public void A_failure_offers_the_methods_of_AuthenticationsThatCanContinue()
        {
            var service = new UserAuthService(_session);
            CollectionAssert.AreEqual(new[] { "password", "publickey" }, (System.Collections.ICollection)service.AuthenticationsThatCanContinue);
            service.AuthenticationsThatCanContinue = new[] { "publickey" };
            service.UserAuth += (_, e) => e.Result = false;

            service.HandleMessageCore(PasswordRequest("wrong-password"));

            Assert.AreEqual(("publickey", false), ReadFailure(ReceivePayload()));
        }

        [TestMethod]
        public async Task Password_partial_success_answers_failure_with_partial_success_and_starts_no_service()
        {
            var service = new UserAuthService(_session);
            service.UserAuth += (_, e) =>
            {
                e.Result = true;
                e.PartialSuccess = true;
            };
            var partial = new List<UserAuthArgs>();
            service.PartialSucceed += (_, e) =>
            {
                partial.Add(e);
                service.AuthenticationsThatCanContinue = new[] { "publickey" };
            };
            var succeeded = false;
            service.Succeed += (_, _) => succeeded = true;
            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(PasswordRequest("right-password"));

            Assert.AreEqual(("publickey", true), ReadFailure(ReceivePayload()));
            Assert.AreEqual(1, partial.Count);
            Assert.AreEqual("password", partial[0].AuthMethod);
            Assert.IsFalse(succeeded);
            await Assert.ThrowsExactlyAsync<TimeoutException>(
                () => registered.Task.WaitAsync(TimeSpan.FromMilliseconds(400)));
        }

        [TestMethod]
        public async Task PublicKey_partial_success_is_raised_only_after_a_valid_signature()
        {
            var sessionId = RandomNumberGenerator.GetBytes(32);
            typeof(Session).GetProperty(nameof(Session.SessionId))!.SetValue(_session, sessionId);

            var service = new UserAuthService(_session);
            service.UserAuth += (_, e) =>
            {
                e.Result = true;
                e.PartialSuccess = true;
            };
            var partial = 0;
            service.PartialSucceed += (_, _) => partial++;
            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            var key = new EcdsaKey("nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp256"));
            var blob = key.CreateKeyAndCertificatesData();

            // The query without a signature gets PK_OK, no partial success.
            service.HandleMessageCore(PublicKeyRequest("ecdsa-sha2-nistp256", blob, hasSignature: false, signature: null));
            Assert.AreEqual(PublicKeyOkMessage.MessageNumber, ReceivePayload()[0]);
            Assert.AreEqual(0, partial);

            // A wrong signature is a plain failure.
            service.HandleMessageCore(PublicKeyRequest("ecdsa-sha2-nistp256", blob, hasSignature: true,
                signature: key.CreateSignatureData("other payload"u8.ToArray())));
            Assert.AreEqual(("password,publickey", false), ReadFailure(ReceivePayload()));
            Assert.AreEqual(0, partial);

            // The signature covers the session id and the request without the signature (RFC 4252 section 7).
            var unsigned = TestMessages.Payload(RequestMessage.MessageNumber)
                .Write(Username, Encoding.UTF8)
                .Write("ssh-connection", Encoding.ASCII)
                .Write("publickey", Encoding.ASCII)
                .Write(true)
                .Write("ecdsa-sha2-nistp256", Encoding.ASCII)
                .WriteBinary(blob)
                .ToByteArray();
            var signed = new SshDataWriter().WriteBinary(sessionId).WriteBytes(unsigned).ToByteArray();
            service.HandleMessageCore(PublicKeyRequest("ecdsa-sha2-nistp256", blob, hasSignature: true,
                signature: key.CreateSignatureData(signed)));

            Assert.AreEqual(("password,publickey", true), ReadFailure(ReceivePayload()));
            Assert.AreEqual(1, partial);
            await Assert.ThrowsExactlyAsync<TimeoutException>(
                () => registered.Task.WaitAsync(TimeSpan.FromMilliseconds(400)));
        }

        private static RequestMessage KeyboardInteractiveRequest() =>
            LoadRequest(
                w => w.Write("keyboard-interactive", Encoding.ASCII),
                w => w.Write("", Encoding.UTF8),
                w => w.Write("", Encoding.UTF8));

        private static InfoResponseMessage InfoResponse(params string[] responses)
        {
            var writer = TestMessages.Payload(InfoResponseMessage.MessageNumber).Write((uint)responses.Length);
            foreach (var response in responses)
                writer.Write(response, Encoding.UTF8);
            var message = new InfoResponseMessage();
            message.Load(writer.ToByteArray());
            return message;
        }

        private static KeyboardInteractiveInfoRequest CodePrompt() =>
            new("", "", new[] { new KeyboardInteractivePrompt("Verification code: ", false) });

        [TestMethod]
        public async Task KeyboardInteractive_sends_the_prompts_and_succeeds_with_the_right_response()
        {
            var service = new UserAuthService(_session);
            var calls = new List<(IReadOnlyList<string>? Responses, string Method, string User)>();
            service.UserAuth += (_, e) =>
            {
                calls.Add((e.Responses?.ToArray(), e.AuthMethod, e.Username));
                if (e.Responses == null)
                    e.InfoRequest = new KeyboardInteractiveInfoRequest("Login", "Enter the code.",
                        new[] { new KeyboardInteractivePrompt("Verification code: ", false), new KeyboardInteractivePrompt("Name: ", true) });
                else
                    e.Result = e.Responses[0] == "123456" && e.Responses[1] == "ü";
            };
            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(KeyboardInteractiveRequest());

            // SSH_MSG_USERAUTH_INFO_REQUEST: name, instruction, language tag, prompts with echo flags (RFC 4256 section 3.2).
            var reader = new SshDataReader(ReceivePayload());
            Assert.AreEqual(InfoRequestMessage.MessageNumber, reader.ReadByte());
            Assert.AreEqual("Login", reader.ReadString(Encoding.UTF8));
            Assert.AreEqual("Enter the code.", reader.ReadString(Encoding.UTF8));
            Assert.AreEqual("", reader.ReadString(Encoding.UTF8));
            Assert.AreEqual(2u, reader.ReadUInt32());
            Assert.AreEqual("Verification code: ", reader.ReadString(Encoding.UTF8));
            Assert.IsFalse(reader.ReadBoolean());
            Assert.AreEqual("Name: ", reader.ReadString(Encoding.UTF8));
            Assert.IsTrue(reader.ReadBoolean());
            Assert.IsFalse(registered.Task.IsCompleted);

            service.HandleMessageCore(InfoResponse("123456", "ü"));

            Assert.AreEqual(SuccessMessage.MessageNumber, ReceivePayload()[0]);
            var svc = await registered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.IsInstanceOfType(svc, typeof(ConnectionService));
            Assert.AreEqual(2, calls.Count);
            Assert.IsNull(calls[0].Responses);
            Assert.AreEqual("keyboard-interactive", calls[0].Method);
            Assert.AreEqual(Username, calls[0].User);
            CollectionAssert.AreEqual(new[] { "123456", "ü" }, (System.Collections.ICollection)calls[1].Responses!);
        }

        [TestMethod]
        public void KeyboardInteractive_with_a_wrong_response_fails()
        {
            var service = new UserAuthService(_session);
            service.UserAuth += (_, e) =>
            {
                if (e.Responses == null)
                    e.InfoRequest = CodePrompt();
                else
                    e.Result = e.Responses[0] == "123456";
            };

            service.HandleMessageCore(KeyboardInteractiveRequest());
            Assert.AreEqual(InfoRequestMessage.MessageNumber, ReceivePayload()[0]);
            service.HandleMessageCore(InfoResponse("654321"));

            Assert.AreEqual(("password,publickey", false), ReadFailure(ReceivePayload()));
        }

        [TestMethod]
        public void KeyboardInteractive_without_prompts_from_the_handler_fails_at_once()
        {
            var service = new UserAuthService(_session);
            service.UserAuth += (_, e) => e.Result = false;

            service.HandleMessageCore(KeyboardInteractiveRequest());

            Assert.AreEqual(("password,publickey", false), ReadFailure(ReceivePayload()));
        }

        [TestMethod]
        public void KeyboardInteractive_with_another_number_of_responses_fails_without_asking_the_handler()
        {
            var service = new UserAuthService(_session);
            var responsesSeen = 0;
            service.UserAuth += (_, e) =>
            {
                if (e.Responses == null)
                    e.InfoRequest = CodePrompt();
                else
                {
                    responsesSeen++;
                    e.Result = true;
                }
            };

            service.HandleMessageCore(KeyboardInteractiveRequest());
            Assert.AreEqual(InfoRequestMessage.MessageNumber, ReceivePayload()[0]);
            service.HandleMessageCore(InfoResponse("123456", "extra"));

            Assert.AreEqual(("password,publickey", false), ReadFailure(ReceivePayload()));
            Assert.AreEqual(0, responsesSeen);
        }

        [TestMethod]
        public async Task KeyboardInteractive_response_without_a_request_is_ignored()
        {
            var service = new UserAuthService(_session);
            var calls = 0;
            service.UserAuth += (_, e) =>
            {
                calls++;
                e.Result = true;
            };
            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(InfoResponse("123456"));

            Assert.AreEqual(0, calls);
            await Assert.ThrowsExactlyAsync<TimeoutException>(
                () => registered.Task.WaitAsync(TimeSpan.FromMilliseconds(400)));
        }

        [TestMethod]
        public void KeyboardInteractive_response_after_a_new_request_belongs_to_the_new_request_only()
        {
            var service = new UserAuthService(_session);
            service.UserAuth += (_, e) =>
            {
                if (e.AuthMethod == "keyboard-interactive" && e.Responses == null)
                    e.InfoRequest = CodePrompt();
                else if (e.Responses != null)
                    e.Result = true;
            };

            service.HandleMessageCore(KeyboardInteractiveRequest());
            Assert.AreEqual(InfoRequestMessage.MessageNumber, ReceivePayload()[0]);
            // A new request (RFC 4256 section 3.4) ends the exchange: the old prompts get no response.
            service.HandleMessageCore(PasswordRequest("wrong-password"));
            Assert.AreEqual(("password,publickey", false), ReadFailure(ReceivePayload()));
            service.HandleMessageCore(InfoResponse("123456"));
            service.HandleMessageCore(PasswordRequest("wrong-password"));

            // The response was ignored: the next packet is the failure of the second password request.
            Assert.AreEqual(("password,publickey", false), ReadFailure(ReceivePayload()));
        }

        [TestMethod]
        public void KeyboardInteractive_partial_success_answers_failure_with_partial_success()
        {
            var service = new UserAuthService(_session);
            service.UserAuth += (_, e) =>
            {
                if (e.Responses == null)
                    e.InfoRequest = CodePrompt();
                else
                {
                    e.Result = true;
                    e.PartialSuccess = true;
                }
            };
            var partial = new List<string>();
            service.PartialSucceed += (_, e) =>
            {
                partial.Add(e.AuthMethod);
                service.AuthenticationsThatCanContinue = new[] { "publickey" };
            };

            service.HandleMessageCore(KeyboardInteractiveRequest());
            Assert.AreEqual(InfoRequestMessage.MessageNumber, ReceivePayload()[0]);
            service.HandleMessageCore(InfoResponse("123456"));

            Assert.AreEqual(("publickey", true), ReadFailure(ReceivePayload()));
            CollectionAssert.AreEqual(new[] { "keyboard-interactive" }, partial);
        }

        [TestMethod]
        public void KeyboardInteractive_can_ask_a_second_round_and_clears_the_responses_afterwards()
        {
            var service = new UserAuthService(_session);
            UserAuthArgs? seen = null;
            var round = 0;
            service.UserAuth += (_, e) =>
            {
                seen = e;
                if (e.Responses == null || round++ == 0)
                    e.InfoRequest = CodePrompt();
                else
                    e.Result = false;
            };

            service.HandleMessageCore(KeyboardInteractiveRequest());
            Assert.AreEqual(InfoRequestMessage.MessageNumber, ReceivePayload()[0]);
            service.HandleMessageCore(InfoResponse("first"));
            Assert.AreEqual(InfoRequestMessage.MessageNumber, ReceivePayload()[0]);
            service.HandleMessageCore(InfoResponse("second"));
            Assert.AreEqual(("password,publickey", false), ReadFailure(ReceivePayload()));

            Assert.AreEqual(0, seen!.Responses!.Count);
        }

        [TestMethod]
        public async Task Hostbased_method_is_rejected()
        {
            var service = new UserAuthService(_session);
            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(LoadRequest(w => w.Write("hostbased", Encoding.ASCII)));

            await Assert.ThrowsExactlyAsync<TimeoutException>(
                () => registered.Task.WaitAsync(TimeSpan.FromMilliseconds(400)));
        }
    }
}
