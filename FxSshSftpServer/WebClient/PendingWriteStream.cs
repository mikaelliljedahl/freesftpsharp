using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// A write-only stream over the response body for <see cref="ZipStreamer"/>. <see cref="System.IO.Compression.ZipArchive"/>
    /// writes some small records (the local header when an entry is finished, the data descriptor) synchronously even in
    /// its asynchronous mode, and the server does not allow synchronous I/O on a response. Such writes are kept here
    /// and sent with the next asynchronous write or <see cref="SendPendingAsync"/>; the file data itself is never kept.
    /// </summary>
    public sealed class PendingWriteStream : Stream
    {
        private readonly Stream _inner;
        private readonly MemoryStream _pending = new();

        public PendingWriteStream(Stream inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        }

        /// <summary>The bytes of the synchronous writes that are not sent yet.</summary>
        public long PendingBytes => _pending.Length;

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count) => _pending.Write(buffer, offset, count);

        public override void Write(ReadOnlySpan<byte> buffer) => _pending.Write(buffer);

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await SendPendingAsync(cancellationToken);
            await _inner.WriteAsync(buffer, cancellationToken);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        /// <summary>Sends the bytes of the synchronous writes.</summary>
        public async Task SendPendingAsync(CancellationToken ct)
        {
            if (_pending.Length == 0)
                return;
            await _inner.WriteAsync(_pending.GetBuffer().AsMemory(0, (int)_pending.Length), ct);
            _pending.SetLength(0);
        }

        public override void Flush()
        {
            // Nothing: a flush of the response is asynchronous (FlushAsync).
        }

        public override async Task FlushAsync(CancellationToken cancellationToken)
        {
            await SendPendingAsync(cancellationToken);
            await _inner.FlushAsync(cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                _pending.Dispose();
            base.Dispose(disposing);
        }
    }
}
