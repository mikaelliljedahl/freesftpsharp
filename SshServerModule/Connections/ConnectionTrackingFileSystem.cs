#nullable enable
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Connections
{
    /// <summary>
    /// A storage decorator that keeps the <see cref="IConnectionRegistry"/> entry of one connection up to date: every
    /// operation records activity, and an open file is an <see cref="ActiveTransfer"/> from its first read or write
    /// (the first one gives the direction) until it is closed, with the bytes read and written so far.
    /// It changes no result and no exception of the storage.
    /// </summary>
    public sealed class ConnectionTrackingFileSystem : IFileSystem
    {
        private readonly IFileSystem _inner;
        private readonly IConnectionRegistry _registry;
        private readonly Guid _connectionId;

        public ConnectionTrackingFileSystem(IFileSystem inner, IConnectionRegistry registry, Guid connectionId)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _registry = registry ?? throw new ArgumentNullException(nameof(registry));
            _connectionId = connectionId;
        }

        public StorageCapabilities Capabilities => _inner.Capabilities;

        public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct)
        {
            Touch();
            return _inner.StatAsync(path, followLinks, ct);
        }

        public async IAsyncEnumerable<FileSystemEntry> ListAsync(string path, [EnumeratorCancellation] CancellationToken ct)
        {
            Touch();
            await foreach (var entry in _inner.ListAsync(path, ct).WithCancellation(ct))
                yield return entry;
        }

        public async ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct)
        {
            Touch();
            var handle = await _inner.OpenAsync(path, flags, initial, ct);
            return new TrackedHandle(handle, _registry, _connectionId, VirtualPath.Normalize(path));
        }

        public ValueTask CreateDirectoryAsync(string path, CancellationToken ct)
        {
            Touch();
            return _inner.CreateDirectoryAsync(path, ct);
        }

        public ValueTask DeleteFileAsync(string path, CancellationToken ct)
        {
            Touch();
            return _inner.DeleteFileAsync(path, ct);
        }

        public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct)
        {
            Touch();
            return _inner.DeleteDirectoryAsync(path, ct);
        }

        public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct)
        {
            Touch();
            return _inner.RenameAsync(oldPath, newPath, flags, ct);
        }

        public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct)
        {
            Touch();
            return _inner.SetAttributesAsync(path, update, ct);
        }

        public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct)
        {
            Touch();
            return _inner.GetStorageSpaceAsync(path, ct);
        }

        private void Touch() => _registry.RecordActivity(_connectionId);

        private sealed class TrackedHandle : IFileHandle
        {
            private readonly IFileHandle _inner;
            private readonly IConnectionRegistry _registry;
            private readonly Guid _connectionId;
            private readonly string _path;
            private readonly object _lock = new();
            private ITransferProgress? _progress;
            private bool _closed;

            public TrackedHandle(IFileHandle inner, IConnectionRegistry registry, Guid connectionId, string path)
            {
                _inner = inner;
                _registry = registry;
                _connectionId = connectionId;
                _path = path;
            }

            public async ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken ct)
            {
                var read = await _inner.ReadAsync(offset, buffer, ct);
                Count(TransferDirection.Download, read);
                return read;
            }

            public async ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct)
            {
                await _inner.WriteAsync(offset, data, ct);
                Count(TransferDirection.Upload, data.Length);
            }

            public ValueTask FlushAsync(CancellationToken ct)
            {
                _registry.RecordActivity(_connectionId);
                return _inner.FlushAsync(ct);
            }

            public ValueTask<FileSystemEntry> StatAsync(CancellationToken ct)
            {
                _registry.RecordActivity(_connectionId);
                return _inner.StatAsync(ct);
            }

            public ValueTask SetAttributesAsync(FileAttributesUpdate update, CancellationToken ct)
            {
                _registry.RecordActivity(_connectionId);
                return _inner.SetAttributesAsync(update, ct);
            }

            public async ValueTask DisposeAsync()
            {
                ITransferProgress? progress;
                lock (_lock)
                {
                    _closed = true;
                    progress = _progress;
                    _progress = null;
                }
                try
                {
                    await _inner.DisposeAsync();
                }
                finally
                {
                    progress?.Dispose();
                }
            }

            private void Count(TransferDirection direction, int bytes)
            {
                ITransferProgress progress;
                lock (_lock)
                {
                    if (_closed)
                        return;
                    progress = _progress ??= _registry.BeginTransfer(_connectionId, _path, direction);
                }
                progress.AddBytes(bytes);
            }
        }
    }
}
