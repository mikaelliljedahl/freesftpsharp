#nullable enable
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Quotas
{
    /// <summary>
    /// The storage rule "bandwidth" (issue #62) for one session: a <see cref="TokenBucket"/> per direction, shared by every
    /// open file of the session. A write waits for its bytes before it reaches the storage; a read waits for the bytes it
    /// read before it returns. The protocol answers the request only then, which throttles SFTP clients (SSH.NET and
    /// OpenSSH keep a fixed number of requests in flight). The wait is asynchronous: the SFTP engine handles the other
    /// requests of the session (a directory list, a STAT, the requests of another file) while a READ or WRITE waits, and
    /// keeps the requests of one handle in order (#133).
    /// </summary>
    public sealed class BandwidthFileSystem : IFileSystem
    {
        private readonly IFileSystem _inner;
        private readonly TokenBucket? _upload;
        private readonly TokenBucket? _download;

        public BandwidthFileSystem(IFileSystem inner, TokenBucket? upload, TokenBucket? download)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _upload = upload;
            _download = download;
        }

        /// <summary>
        /// The decorator around <paramref name="inner"/> with these rates in bytes per second (0: unlimited), or
        /// <paramref name="inner"/> itself when both are unlimited.
        /// </summary>
        public static IFileSystem Wrap(IFileSystem inner, long uploadBytesPerSecond, long downloadBytesPerSecond, TimeProvider? time = null)
            => uploadBytesPerSecond <= 0 && downloadBytesPerSecond <= 0
                ? inner
                : new BandwidthFileSystem(inner,
                    uploadBytesPerSecond > 0 ? new TokenBucket(uploadBytesPerSecond, time: time) : null,
                    downloadBytesPerSecond > 0 ? new TokenBucket(downloadBytesPerSecond, time: time) : null);

        public StorageCapabilities Capabilities => _inner.Capabilities;

        public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct) => _inner.StatAsync(path, followLinks, ct);

        public IAsyncEnumerable<FileSystemEntry> ListAsync(string path, CancellationToken ct) => _inner.ListAsync(path, ct);

        public async ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct)
            => new Handle(this, await _inner.OpenAsync(path, flags, initial, ct));

        public ValueTask CreateDirectoryAsync(string path, CancellationToken ct) => _inner.CreateDirectoryAsync(path, ct);

        public ValueTask DeleteFileAsync(string path, CancellationToken ct) => _inner.DeleteFileAsync(path, ct);

        public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct) => _inner.DeleteDirectoryAsync(path, ct);

        public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct) => _inner.RenameAsync(oldPath, newPath, flags, ct);

        public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct) => _inner.SetAttributesAsync(path, update, ct);

        public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct) => _inner.GetStorageSpaceAsync(path, ct);

        private sealed class Handle : IFileHandle
        {
            private readonly BandwidthFileSystem _owner;
            private readonly IFileHandle _inner;

            public Handle(BandwidthFileSystem owner, IFileHandle inner)
            {
                _owner = owner;
                _inner = inner;
            }

            public async ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken ct)
            {
                var read = await _inner.ReadAsync(offset, buffer, ct);
                if (_owner._download is { } bucket)
                    await bucket.WaitAsync(read, ct);
                return read;
            }

            public async ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct)
            {
                if (_owner._upload is { } bucket)
                    await bucket.WaitAsync(data.Length, ct);
                await _inner.WriteAsync(offset, data, ct);
            }

            public ValueTask FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);

            public ValueTask<FileSystemEntry> StatAsync(CancellationToken ct) => _inner.StatAsync(ct);

            public ValueTask SetAttributesAsync(FileAttributesUpdate update, CancellationToken ct) => _inner.SetAttributesAsync(update, ct);

            public ValueTask DisposeAsync() => _inner.DisposeAsync();

            public ValueTask AbortAsync() => _inner.AbortAsync();
        }
    }
}
