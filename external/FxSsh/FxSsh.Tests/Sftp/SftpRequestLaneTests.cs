using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.Services;
using FxSsh.Services.Sftp;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Sftp
{
    /// <summary>
    /// The request lanes of <see cref="SftpService"/> (freesftpsharp #133): a waiting READ or WRITE does not hold the
    /// other requests, the requests of one handle stay in order, the window and the replies are bounded, and the close
    /// is safe in any order.
    /// </summary>
    [TestClass]
    public sealed class SftpRequestLaneTests
    {
        private const byte SSH_FXP_INIT = 1;
        private const byte SSH_FXP_VERSION = 2;
        private const byte SSH_FXP_OPEN = 3;
        private const byte SSH_FXP_READ = 5;
        private const byte SSH_FXP_WRITE = 6;
        private const byte SSH_FXP_STAT = 17;
        private const byte SSH_FXP_STATUS = 101;
        private const byte SSH_FXP_HANDLE = 102;
        private const byte SSH_FXP_ATTRS = 105;
        private const uint SSH_FX_OK = 0;
        private const uint SSH_FX_FAILURE = 4;

        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private Socket _clientSocket = null!;
        private Socket _serverSocket = null!;
        private Session _session = null!;
        private ConnectionService _connection = null!;

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
            _connection = new ConnectionService(_session, new UserAuthArgs(_session));
        }

        [TestCleanup]
        public void DisposeSockets()
        {
            _clientSocket.Dispose();
            _serverSocket.Dispose();
        }

        [TestMethod]
        public void A_waiting_write_does_not_hold_a_stat_and_the_writes_of_one_handle_stay_in_order()
        {
            var fileSystem = new GatedFileSystem();
            using var engine = new Engine(new SftpService(fileSystem));
            var handle = engine.Open();

            for (uint id = 2; id <= 4; id++)
                engine.Service.OnData(Write(id, handle, (ulong)(id - 2), (byte)id));
            engine.Service.OnData(Request(SSH_FXP_STAT, 5, w => w.Write("/a.bin", Encoding.UTF8)));

            var first = engine.Take();
            Assert.AreEqual((SSH_FXP_ATTRS, 5u), (first.Type, first.Id), "The STAT must be answered while the write waits.");
            CollectionAssert.AreEqual(new[] { 2 }, fileSystem.File.Started);

            fileSystem.File.Gate.SetResult();
            var replies = new[] { engine.Take(), engine.Take(), engine.Take() };
            CollectionAssert.AreEqual(new uint[] { 2, 3, 4 }, Array.ConvertAll(replies, r => r.Id));
            foreach (var reply in replies)
                Assert.AreEqual(SSH_FX_OK, reply.StatusCode);
            CollectionAssert.AreEqual(new[] { 2, 3, 4 }, fileSystem.File.Written);
        }

        [TestMethod]
        public void A_close_cancels_a_waiting_write_and_releases_the_handle_when_it_stopped()
        {
            var fileSystem = new GatedFileSystem();
            var engine = new Engine(new SftpService(fileSystem));
            var handle = engine.Open();
            var closed = new ManualResetEventSlim();
            engine.Service.CloseReceived += (_, _) => closed.Set();
            engine.Service.OnData(Write(2, handle, 0, 1));

            engine.Service.OnClose(); // does not wait for the write

            Assert.IsTrue(closed.Wait(Timeout), "CloseReceived must follow when the write stopped.");
            Assert.IsTrue(fileSystem.File.Cancelled);
            Assert.IsTrue(fileSystem.File.Aborted);
            Assert.AreEqual(0, fileSystem.File.Written.Length);
            engine.Dispose();
        }

        [TestMethod]
        public void A_request_after_the_close_is_answered_with_failure_without_the_file_system()
        {
            var fileSystem = new GatedFileSystem();
            using var engine = new Engine(new SftpService(fileSystem));
            engine.Service.OnClose();

            engine.Service.OnData(Request(SSH_FXP_STAT, 7, w => w.Write("/a.bin", Encoding.UTF8)));

            var reply = engine.Take();
            Assert.AreEqual((SSH_FXP_STATUS, 7u, SSH_FX_FAILURE), (reply.Type, reply.Id, reply.StatusCode));
            Assert.AreEqual(0, fileSystem.Stats);
        }

        [TestMethod]
        public async Task An_open_that_completes_after_the_close_started_aborts_its_handle()
        {
            var fileSystem = new GatedFileSystem { OpenGate = new ManualResetEventSlim() };
            using var engine = new Engine(new SftpService(fileSystem));
            var open = Task.Run(() => engine.Service.OnData(OpenRequest(1)));
            Assert.IsTrue(fileSystem.OpenStarted.Wait(Timeout));

            engine.Service.OnClose();
            fileSystem.OpenGate.Set();
            await open.WaitAsync(Timeout);

            var reply = engine.Take();
            Assert.AreEqual((SSH_FXP_STATUS, 1u, SSH_FX_FAILURE), (reply.Type, reply.Id, reply.StatusCode));
            Assert.IsTrue(fileSystem.File.Aborted, "The handle of the late OPEN must be released.");
        }

        [TestMethod]
        public void Dispose_close_and_dispose_again_are_safe_in_any_order()
        {
            var service = new SftpService(new GatedFileSystem());
            service.Dispose();
            service.OnClose();
            service.Dispose();

            var other = new SftpService(new GatedFileSystem());
            other.OnClose();
            other.Dispose();
        }

        [TestMethod]
        public void A_forced_close_after_dispose_does_not_throw()
        {
            var channel = new SessionChannel(_connection, 1, 1000, 32768, 1000);
            var service = new SftpService(new GatedFileSystem());
            service.Attach(channel);
            service.Dispose();

            channel.ForceClose();
        }

        [TestMethod]
        public void The_window_goes_back_to_the_peer_only_when_the_consumer_releases_it()
        {
            var channel = new SessionChannel(_connection, 1, 1000, 32768, 1000);
            channel.DeferWindowAdjust();
            var initial = channel.ServerInitialWindowSize;
            var chunk = new byte[Session.LocalChannelDataPacketSize];

            for (var i = 0; i < 48; i++) // 1.5 MiB: below half of the window
                channel.OnData(chunk);
            Assert.AreEqual(initial - 48u * (uint)chunk.Length, channel.ServerWindowSize, "No adjust before a release.");

            channel.ReleaseWindow(16u * (uint)chunk.Length);
            Assert.AreEqual(initial - 32u * (uint)chunk.Length, channel.ServerWindowSize, "Only the released bytes go back.");

            // The peer has half of the window again: no adjust is needed yet (as without deferral).
            channel.ReleaseWindow(32u * (uint)chunk.Length);
            Assert.AreEqual(initial - 32u * (uint)chunk.Length, channel.ServerWindowSize);

            // Below half, a release tops the window up to the initial size.
            channel.OnData(chunk);
            channel.ReleaseWindow((uint)chunk.Length);
            Assert.AreEqual(initial, channel.ServerWindowSize);
        }

        [TestMethod]
        public void Waiting_writes_hold_the_window_of_their_requests()
        {
            var channel = new SessionChannel(_connection, 1, 1u << 30, 32768, 1000);
            var fileSystem = new GatedFileSystem();
            var service = new SftpService(fileSystem);
            service.Attach(channel);
            var handle = OpenOver(channel, fileSystem);
            var before = channel.ServerWindowSize;
            var data = new byte[30000];

            for (uint id = 2; id < 40; id++) // more than half of the window, all wait for the gate
                channel.OnData(Write(id, handle, 0, data));

            Assert.IsTrue(channel.ServerWindowSize < before - 30000u * 37, "The window of the waiting requests must stay used.");
            fileSystem.File.Gate.SetResult();
            Assert.IsTrue(SpinWait.SpinUntil(() => channel.ServerWindowSize >= channel.ServerInitialWindowSize / 2, Timeout),
                "The window must go back when the requests are answered.");
            channel.ForceClose();
        }

        [TestMethod]
        public void Reads_stop_while_the_replies_wait_for_the_peer_window()
        {
            // The peer grants no window: the replies stay in the outbound queue.
            var channel = new SessionChannel(_connection, 1, 0, 32768, 1000);
            var fileSystem = new GatedFileSystem();
            var service = new SftpService(fileSystem);
            service.Attach(channel);
            fileSystem.File.Gate.SetResult();
            var handle = OpenOver(channel, fileSystem);

            for (uint id = 2; id < 102; id++)
                channel.OnData(Request(SSH_FXP_READ, id, w =>
                {
                    w.Write(handle, Encoding.ASCII);
                    w.Write(0ul);
                    w.Write(64u * 1024);
                }));

            // 4 MiB of 64 KiB replies, then the reads wait.
            Assert.AreEqual(64, fileSystem.File.Reads);
            channel.ForceClose();
        }

        // ---- helpers ----

        private static string OpenOver(SessionChannel channel, GatedFileSystem fileSystem)
        {
            channel.OnData(Init());
            channel.OnData(OpenRequest(1));
            Assert.IsNotNull(fileSystem.LastOpened);
            return "1"; // the first handle of the engine
        }

        private static byte[] Frame(Action<SshDataWriter> writePayload)
        {
            var payload = new SshDataWriter();
            writePayload(payload);
            var bytes = payload.ToByteArray();
            var frame = new byte[4 + bytes.Length];
            frame[0] = (byte)(bytes.Length >> 24);
            frame[1] = (byte)(bytes.Length >> 16);
            frame[2] = (byte)(bytes.Length >> 8);
            frame[3] = (byte)bytes.Length;
            bytes.CopyTo(frame, 4);
            return frame;
        }

        private static byte[] Init() => Frame(w =>
        {
            w.Write(SSH_FXP_INIT);
            w.Write(3u);
        });

        private static byte[] Request(byte type, uint id, Action<SshDataWriter> fields) => Frame(w =>
        {
            w.Write(type);
            w.Write(id);
            fields(w);
        });

        private static byte[] OpenRequest(uint id) => Request(SSH_FXP_OPEN, id, w =>
        {
            w.Write("/a.bin", Encoding.UTF8);
            w.Write((uint)(SftpOpenFlags.Write | SftpOpenFlags.Read | SftpOpenFlags.Create));
            new SftpFileAttributes().Write(w);
        });

        private static byte[] Write(uint id, string handle, ulong offset, byte value) => Write(id, handle, offset, new[] { value });

        private static byte[] Write(uint id, string handle, ulong offset, byte[] data) => Request(SSH_FXP_WRITE, id, w =>
        {
            w.Write(handle, Encoding.ASCII);
            w.Write(offset);
            w.WriteBinary((ReadOnlySpan<byte>)data);
        });

        private sealed record Reply(byte Type, uint Id, SshDataReader Payload)
        {
            public uint StatusCode
            {
                get
                {
                    Assert.AreEqual(SSH_FXP_STATUS, Type);
                    return Payload.ReadUInt32();
                }
            }

            public static Reply Parse(byte[] packet)
            {
                var reader = new SshDataReader(packet);
                var length = reader.ReadUInt32();
                var payload = new SshDataReader(reader.ReadBytes((int)length));
                var type = payload.ReadByte();
                var id = type == SSH_FXP_VERSION ? 0u : payload.ReadUInt32();
                return new Reply(type, id, payload);
            }
        }

        private sealed class Engine : IDisposable
        {
            private readonly BlockingCollection<Reply> _replies = new();

            public Engine(SftpService service)
            {
                Service = service;
                Service.DataReceived += (_, packet) => _replies.Add(Reply.Parse(packet));
            }

            public SftpService Service { get; }

            public Reply Take()
            {
                Assert.IsTrue(_replies.TryTake(out var reply, Timeout), "No reply in time.");
                return reply!;
            }

            public string Open()
            {
                Service.OnData(Init());
                Assert.AreEqual(SSH_FXP_VERSION, Take().Type);
                Service.OnData(OpenRequest(1));
                var reply = Take();
                Assert.AreEqual(SSH_FXP_HANDLE, reply.Type);
                return reply.Payload.ReadString(Encoding.ASCII);
            }

            public void Dispose() => Service.Dispose();
        }

        /// <summary>One file; its WRITEs wait until <see cref="GatedFile.Gate"/> is set.</summary>
        private sealed class GatedFileSystem : ISftpFileSystem
        {
            public GatedFile File { get; } = new();
            public ManualResetEventSlim? OpenGate { get; init; }
            public ManualResetEventSlim OpenStarted { get; } = new();
            public GatedFile? LastOpened { get; private set; }
            public int Stats { get; private set; }

            public ISftpFileHandle OpenFile(string path, SftpOpenFlags flags, SftpFileAttributes attributes)
            {
                OpenStarted.Set();
                OpenGate?.Wait(Timeout);
                return LastOpened = File;
            }

            public ISftpDirectoryHandle OpenDirectory(string path) => throw new NotSupportedException();

            public SftpFileAttributes GetAttributes(string path, bool followLinks)
            {
                Stats++;
                return new SftpFileAttributes { Size = 0 };
            }

            public void SetAttributes(string path, SftpFileAttributes attributes) => throw new NotSupportedException();
            public void RemoveFile(string path) => throw new NotSupportedException();
            public void Rename(string oldPath, string newPath) => throw new NotSupportedException();
            public void MakeDirectory(string path, SftpFileAttributes attributes) => throw new NotSupportedException();
            public void RemoveDirectory(string path) => throw new NotSupportedException();
            public string RealPath(string path) => path;
        }

        private sealed class GatedFile : ISftpAsyncFileHandle
        {
            private readonly ConcurrentQueue<int> _started = new();
            private readonly ConcurrentQueue<int> _written = new();
            private int _reads;

            public TaskCompletionSource Gate { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public int[] Started => _started.ToArray();
            public int[] Written => _written.ToArray();
            public int Reads => Volatile.Read(ref _reads);
            public bool Cancelled { get; private set; }
            public bool Aborted { get; private set; }

            public async ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
            {
                _started.Enqueue(data.Span[0]);
                try
                {
                    await Gate.Task.WaitAsync(cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    Cancelled = true;
                    throw;
                }
                _written.Enqueue(data.Span[0]);
            }

            public ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken cancellationToken)
            {
                Interlocked.Increment(ref _reads);
                return ValueTask.FromResult(buffer.Length);
            }

            public int Read(long offset, Span<byte> buffer) => throw new InvalidOperationException("The engine must use ReadAsync.");
            public void Write(long offset, ReadOnlySpan<byte> data) => throw new InvalidOperationException("The engine must use WriteAsync.");
            public SftpFileAttributes GetAttributes() => new();
            public void SetAttributes(SftpFileAttributes attributes) { }
            public void Dispose() { }
            public void Abort() => Aborted = true;
        }
    }
}
