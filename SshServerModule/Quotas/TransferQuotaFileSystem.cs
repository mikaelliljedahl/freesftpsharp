#nullable enable
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Quotas
{
    /// <summary>
    /// The storage rule "transfer quota" (issue #62) for the sessions of one user: every read and write of an open file
    /// counts in the user's transfer counters (<see cref="QuotaUsageTracker"/>), whatever the storage. A write that would
    /// go over <see cref="TransferQuota.MaxUploadBytes"/> or <see cref="TransferQuota.MaxTotalBytes"/> fails with
    /// <see cref="FileSystemError.QuotaExceeded"/>; a read gets at most the bytes that are left, and fails when none are left.
    /// The counters start again at 0 when an administrator resets them.
    /// </summary>
    public sealed class TransferQuotaFileSystem : IFileSystem
    {
        private readonly IFileSystem _inner;
        private readonly QuotaUsageTracker _tracker;
        private readonly QuotaScope _scope;
        private readonly TransferQuota _limit;

        public TransferQuotaFileSystem(IFileSystem inner, QuotaUsageTracker tracker, QuotaScope scope, TransferQuota limit)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
            _scope = scope;
            _limit = limit ?? throw new ArgumentNullException(nameof(limit));
        }

        /// <summary>The decorator around <paramref name="inner"/>, or <paramref name="inner"/> itself without a limit.</summary>
        public static IFileSystem Wrap(IFileSystem inner, QuotaUsageTracker tracker, QuotaScope scope, TransferQuota? limit)
            => TransferQuota.OrNull(limit) is { } quota ? new TransferQuotaFileSystem(inner, tracker, scope, quota) : inner;

        public StorageCapabilities Capabilities => _inner.Capabilities;

        public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct) => _inner.StatAsync(path, followLinks, ct);

        public IAsyncEnumerable<FileSystemEntry> ListAsync(string path, CancellationToken ct) => _inner.ListAsync(path, ct);

        public async ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct)
            => new Handle(this, await _inner.OpenAsync(path, flags, initial, ct), path);

        public ValueTask CreateDirectoryAsync(string path, CancellationToken ct) => _inner.CreateDirectoryAsync(path, ct);

        public ValueTask DeleteFileAsync(string path, CancellationToken ct) => _inner.DeleteFileAsync(path, ct);

        public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct) => _inner.DeleteDirectoryAsync(path, ct);

        public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct) => _inner.RenameAsync(oldPath, newPath, flags, ct);

        public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct) => _inner.SetAttributesAsync(path, update, ct);

        public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct) => _inner.GetStorageSpaceAsync(path, ct);

        private FileSystemException Exceeded(string path)
            => new(FileSystemError.QuotaExceeded, $"Quota exceeded: {VirtualPath.Normalize(path)} (transfer quota)");

        private sealed class Handle : IFileHandle
        {
            private readonly TransferQuotaFileSystem _owner;
            private readonly IFileHandle _inner;
            private readonly string _path;

            public Handle(TransferQuotaFileSystem owner, IFileHandle inner, string path)
            {
                _owner = owner;
                _inner = inner;
                _path = path;
            }

            public async ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken ct)
            {
                var allowance = _owner._tracker.DownloadAllowance(_owner._scope, _owner._limit);
                if (allowance <= 0 && buffer.Length > 0)
                    throw _owner.Exceeded(_path);
                var read = await _inner.ReadAsync(offset, buffer[..(int)Math.Min(buffer.Length, allowance)], ct);
                _owner._tracker.AddTransfer(_owner._scope, 0, read);
                return read;
            }

            public async ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct)
            {
                if (!_owner._tracker.TryAddUpload(_owner._scope, _owner._limit, data.Length))
                    throw _owner.Exceeded(_path);
                try
                {
                    await _inner.WriteAsync(offset, data, ct);
                }
                catch
                {
                    _owner._tracker.AddTransfer(_owner._scope, -data.Length, 0);
                    throw;
                }
            }

            public ValueTask FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);

            public ValueTask<FileSystemEntry> StatAsync(CancellationToken ct) => _inner.StatAsync(ct);

            public ValueTask SetAttributesAsync(FileAttributesUpdate update, CancellationToken ct) => _inner.SetAttributesAsync(update, ct);

            public ValueTask DisposeAsync() => _inner.DisposeAsync();

            public ValueTask AbortAsync() => _inner.AbortAsync();
        }
    }
}
