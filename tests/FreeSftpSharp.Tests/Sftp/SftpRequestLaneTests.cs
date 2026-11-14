using System.Collections.Concurrent;
using System.Text;
using FxSsh.Services.Sftp;
using static FreeSftpSharp.Tests.Sftp.SftpEngineClient;

namespace FreeSftpSharp.Tests.Sftp;

/// <summary>
/// Issue #133: a READ or WRITE of an <see cref="ISftpAsyncFileHandle"/> that waits does not hold the other requests of
/// the session, and the requests of one handle stay in the order of the client.
/// </summary>
public sealed class SftpRequestLaneTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    [Fact]
    public void A_waiting_write_does_not_hold_a_stat_and_the_writes_of_one_handle_stay_in_order()
    {
        var fileSystem = new GatedFileSystem();
        using var service = new SftpService(fileSystem);
        var responses = new BlockingCollection<Response>();
        service.DataReceived += (_, packet) => responses.Add(Response.Parse(packet));

        service.OnData(Init());
        Assert.Equal(SSH_FXP_VERSION, Take(responses).Type);
        service.OnData(Request(SSH_FXP_OPEN, 1, w =>
        {
            w.Write("/a.bin", Encoding.UTF8);
            w.Write((uint)(SftpOpenFlags.Write | SftpOpenFlags.Create));
            new SftpFileAttributes().Write(w);
        }));
        var handle = Take(responses).Payload.ReadString(Encoding.ASCII);

        // Three writes on the handle: the first waits until the gate opens.
        for (uint id = 2; id <= 4; id++)
        {
            var offset = (ulong)(id - 2);
            service.OnData(Request(SSH_FXP_WRITE, id, w =>
            {
                w.Write(handle, Encoding.ASCII);
                w.Write(offset);
                w.WriteBinary((ReadOnlySpan<byte>)[(byte)id]);
            }));
        }
        service.OnData(PathRequest(SSH_FXP_STAT, 5, "/a.bin"));

        var first = Take(responses);
        Assert.Equal((SSH_FXP_ATTRS, 5u), (first.Type, first.Id)); // answered while the write waits
        Assert.Equal([2], fileSystem.File.Started);

        fileSystem.File.Gate.SetResult();
        var ids = new[] { Take(responses), Take(responses), Take(responses) };
        Assert.Equal([2u, 3u, 4u], ids.Select(r => r.Id));
        Assert.All(ids, r => Assert.Equal(SSH_FX_OK, r.StatusCode));
        Assert.Equal([2, 3, 4], fileSystem.File.Written);
    }

    [Fact]
    public void A_close_of_the_session_cancels_a_waiting_write_and_closes_the_handle()
    {
        var fileSystem = new GatedFileSystem();
        var service = new SftpService(fileSystem);
        var responses = new BlockingCollection<Response>();
        service.DataReceived += (_, packet) => responses.Add(Response.Parse(packet));
        service.OnData(Init());
        Take(responses);
        service.OnData(Request(SSH_FXP_OPEN, 1, w =>
        {
            w.Write("/a.bin", Encoding.UTF8);
            w.Write((uint)(SftpOpenFlags.Write | SftpOpenFlags.Create));
            new SftpFileAttributes().Write(w);
        }));
        var handle = Take(responses).Payload.ReadString(Encoding.ASCII);
        service.OnData(Request(SSH_FXP_WRITE, 2, w =>
        {
            w.Write(handle, Encoding.ASCII);
            w.Write(0ul);
            w.WriteBinary((ReadOnlySpan<byte>)[1]);
        }));

        var closed = new ManualResetEventSlim();
        service.CloseReceived += (_, _) => closed.Set();

        service.OnClose(); // does not wait; the handles are released when the cancelled write has stopped

        Assert.True(closed.Wait(Timeout, TestContext.Current.CancellationToken), "CloseReceived must follow when the write stopped.");
        Assert.True(fileSystem.File.Cancelled);
        Assert.True(fileSystem.File.Aborted);
        Assert.Empty(fileSystem.File.Written);
        service.Dispose();
    }

    private static Response Take(BlockingCollection<Response> responses)
    {
        Assert.True(responses.TryTake(out var response, Timeout), "No response in time.");
        return response!;
    }

    /// <summary>One file; its first WRITE waits until <see cref="GatedFile.Gate"/> is set.</summary>
    private sealed class GatedFileSystem : ISftpFileSystem
    {
        public GatedFile File { get; } = new();

        public ISftpFileHandle OpenFile(string path, SftpOpenFlags flags, SftpFileAttributes attributes) => File;
        public ISftpDirectoryHandle OpenDirectory(string path) => throw new NotSupportedException();
        public SftpFileAttributes GetAttributes(string path, bool followLinks) => new() { Size = 0 };
        public void SetAttributes(string path, SftpFileAttributes attributes) => throw new NotSupportedException();
        public void RemoveFile(string path) => throw new NotSupportedException();
        public void Rename(string oldPath, string newPath) => throw new NotSupportedException();
        public void MakeDirectory(string path, SftpFileAttributes attributes) => throw new NotSupportedException();
        public void RemoveDirectory(string path) => throw new NotSupportedException();
        public string RealPath(string path) => path;
    }

    private sealed class GatedFile : ISftpAsyncFileHandle
    {
        public TaskCompletionSource Gate { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ConcurrentQueue<int> StartedQueue { get; } = new();
        public int[] Started => [.. StartedQueue];
        private readonly ConcurrentQueue<int> _written = new();
        public int[] Written => [.. _written];
        public bool Cancelled { get; private set; }
        public bool Aborted { get; private set; }

        public async ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
        {
            StartedQueue.Enqueue(data.Span[0]);
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

        public ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken cancellationToken) => ValueTask.FromResult(0);
        public int Read(long offset, Span<byte> buffer) => throw new InvalidOperationException("The engine must use ReadAsync.");
        public void Write(long offset, ReadOnlySpan<byte> data) => throw new InvalidOperationException("The engine must use WriteAsync.");
        public SftpFileAttributes GetAttributes() => new();
        public void SetAttributes(SftpFileAttributes attributes) { }
        public void Dispose() { }
        public void Abort() => Aborted = true;
    }
}
