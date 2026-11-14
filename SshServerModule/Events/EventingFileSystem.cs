#nullable enable
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Events
{
    /// <summary>
    /// The storage decorator of the events (#65): publishes a <see cref="FileEvent"/> for every change and transfer
    /// on the <see cref="IEventBus"/>, and asks the hooks before an upload, a download and a delete.
    /// <list type="bullet">
    /// <item>Open for writing: <c>PreUpload</c> (a hook can refuse it: <see cref="FileSystemError.PermissionDenied"/>, and
    /// the storage is not touched), then at the close <c>Upload</c> with the file size and the time from open to close,
    /// and <c>FirstUpload</c> when the file was new.</item>
    /// <item>Open for reading only: <c>PreDownload</c>, then at the close <c>Download</c> with the bytes read.</item>
    /// <item>Remove a file: <c>PreDelete</c>, then <c>Delete</c>. Rename, create and remove a directory: one event.</item>
    /// </list>
    /// A failed operation gives its event with <see cref="FileEventStatus.Error"/> (or <see cref="FileEventStatus.QuotaExceeded"/>)
    /// and the original exception is thrown. Reads of metadata (stat, list, space) and attribute changes give no event.
    /// </summary>
    public sealed class EventingFileSystem : IFileSystem
    {
        private readonly IFileSystem _inner;
        private readonly IEventBus _events;
        private readonly User _user;
        private readonly ClientContext _client;
        private readonly string? _provider;
        private readonly TimeProvider _time;

        /// <param name="provider">The name of the storage provider, for the events.</param>
        public EventingFileSystem(IFileSystem inner, IEventBus events, User user, ClientContext client, string? provider, TimeProvider time)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _events = events ?? throw new ArgumentNullException(nameof(events));
            _user = user ?? throw new ArgumentNullException(nameof(user));
            _client = client ?? throw new ArgumentNullException(nameof(client));
            _provider = provider;
            _time = time ?? throw new ArgumentNullException(nameof(time));
        }

        public StorageCapabilities Capabilities => _inner.Capabilities;

        public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct) => _inner.StatAsync(path, followLinks, ct);

        public IAsyncEnumerable<FileSystemEntry> ListAsync(string path, CancellationToken ct) => _inner.ListAsync(path, ct);

        public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct) => _inner.SetAttributesAsync(path, update, ct);

        public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct) => _inner.GetStorageSpaceAsync(path, ct);

        public async ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct)
        {
            var upload = (flags & FileOpenFlags.Write) != 0;
            var normalized = VirtualPath.Normalize(path);
            var start = _time.GetTimestamp();

            var isNew = false;
            if (upload && (flags & FileOpenFlags.Create) != 0)
                isNew = await TryStatAsync(normalized, followLinks: true, ct) is (true, null);

            var pre = NewEvent(upload ? FileEventType.PreUpload : FileEventType.PreDownload, normalized) with { OpenFlags = flags };
            await AskAsync(pre, ct);

            IFileHandle handle;
            try
            {
                handle = await _inner.OpenAsync(path, flags, initial, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                await PublishFailedAsync(pre with { Type = upload ? FileEventType.Upload : FileEventType.Download, Elapsed = _time.GetElapsedTime(start) }, ex);
                throw;
            }
            return new EventingFileHandle(this, handle, normalized, flags, upload, isNew, start);
        }

        public async ValueTask CreateDirectoryAsync(string path, CancellationToken ct)
        {
            var e = NewEvent(FileEventType.Mkdir, VirtualPath.Normalize(path));
            await RunAsync(e, () => _inner.CreateDirectoryAsync(path, ct));
        }

        public async ValueTask DeleteFileAsync(string path, CancellationToken ct)
        {
            var normalized = VirtualPath.Normalize(path);
            var (_, entry) = await TryStatAsync(normalized, followLinks: false, ct);
            var pre = NewEvent(FileEventType.PreDelete, normalized) with { FileSize = entry is { IsDirectory: false } ? entry.Size : null };
            await AskAsync(pre, ct);
            await RunAsync(pre with { Type = FileEventType.Delete }, () => _inner.DeleteFileAsync(path, ct));
        }

        public async ValueTask DeleteDirectoryAsync(string path, CancellationToken ct)
        {
            var e = NewEvent(FileEventType.Rmdir, VirtualPath.Normalize(path));
            await RunAsync(e, () => _inner.DeleteDirectoryAsync(path, ct));
        }

        public async ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct)
        {
            var e = NewEvent(FileEventType.Rename, VirtualPath.Normalize(oldPath)) with { VirtualTargetPath = VirtualPath.Normalize(newPath) };
            await RunAsync(e, () => _inner.RenameAsync(oldPath, newPath, flags, ct));
        }

        /// <summary>
        /// The entry for the values of an event. The inner chain can refuse the stat (for example the permissions without
        /// List); then the value is unknown and the operation itself gives the error.
        /// </summary>
        private async ValueTask<(bool Known, FileSystemEntry? Entry)> TryStatAsync(string path, bool followLinks, CancellationToken ct)
        {
            try
            {
                return (true, await _inner.StatAsync(path, followLinks, ct));
            }
            catch (FileSystemException)
            {
                return (false, null);
            }
        }

        private FileEvent NewEvent(FileEventType type, string normalizedPath) => new(type)
        {
            Timestamp = _time.GetUtcNow(),
            Username = _user.Username,
            VirtualPath = normalizedPath,
            Provider = _provider,
            Protocol = _client.Protocol,
            RemoteIp = _client.RemoteIp,
            SessionId = _client.ConnectionId?.ToString(),
        };

        /// <summary>Asks the hooks; publishes the <c>Pre*</c> event with the answer, and throws PermissionDenied for a deny.</summary>
        private async ValueTask AskAsync(FileEvent pre, CancellationToken ct)
        {
            var decision = await _events.AskAsync(pre, ct);
            if (decision.IsDenied)
            {
                await _events.PublishAsync(pre with { Status = FileEventStatus.Denied, Message = decision.Message }, CancellationToken.None);
                throw new FileSystemException(FileSystemError.PermissionDenied, $"Permission denied: {pre.VirtualPath}")
                {
                    ClientMessage = decision.ClientMessage,
                };
            }
            await _events.PublishAsync(pre, CancellationToken.None);
        }

        private async ValueTask RunAsync(FileEvent e, Func<ValueTask> operation)
        {
            var start = _time.GetTimestamp();
            try
            {
                await operation();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                await PublishFailedAsync(e with { Timestamp = _time.GetUtcNow(), Elapsed = _time.GetElapsedTime(start) }, ex);
                throw;
            }
            await _events.PublishAsync(e with { Timestamp = _time.GetUtcNow(), Elapsed = _time.GetElapsedTime(start) }, CancellationToken.None);
        }

        private ValueTask PublishFailedAsync(FileEvent e, Exception ex)
            => _events.PublishAsync(e with
            {
                Timestamp = _time.GetUtcNow(),
                Status = ex is FileSystemException { Error: FileSystemError.QuotaExceeded } ? FileEventStatus.QuotaExceeded : FileEventStatus.Error,
                // The message of a FileSystemException has only virtual paths; another exception is a bug of the storage.
                Message = ex is FileSystemException ? ex.Message : "Internal error of the storage.",
            }, CancellationToken.None);

        /// <summary>Counts the bytes of a transfer and publishes <c>Upload</c> or <c>Download</c> at the close.</summary>
        private sealed class EventingFileHandle : IFileHandle
        {
            private readonly EventingFileSystem _owner;
            private readonly IFileHandle _inner;
            private readonly string _path;
            private readonly FileOpenFlags _flags;
            private readonly bool _upload;
            private readonly bool _isNew;
            private readonly long _start;
            private long _bytesRead;
            private Exception? _failure;
            private int _disposed;

            public EventingFileHandle(EventingFileSystem owner, IFileHandle inner, string path, FileOpenFlags flags, bool upload, bool isNew, long start)
            {
                _owner = owner;
                _inner = inner;
                _path = path;
                _flags = flags;
                _upload = upload;
                _isNew = isNew;
                _start = start;
            }

            public async ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken ct)
            {
                var read = await _inner.ReadAsync(offset, buffer, ct);
                Interlocked.Add(ref _bytesRead, read);
                return read;
            }

            public async ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct)
            {
                try
                {
                    await _inner.WriteAsync(offset, data, ct);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _failure ??= ex;
                    throw;
                }
            }

            public ValueTask FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);

            public ValueTask<FileSystemEntry> StatAsync(CancellationToken ct) => _inner.StatAsync(ct);

            public ValueTask SetAttributesAsync(FileAttributesUpdate update, CancellationToken ct) => _inner.SetAttributesAsync(update, ct);

            public async ValueTask DisposeAsync()
            {
                if (Interlocked.Exchange(ref _disposed, 1) != 0)
                    return;

                long? size = Interlocked.Read(ref _bytesRead);
                if (_upload)
                {
                    try
                    {
                        size = (await _inner.StatAsync(CancellationToken.None)).Size; // includes the data that is not flushed yet
                    }
                    catch (Exception ex) when (ex is FileSystemException)
                    {
                        size = null;
                    }
                }

                try
                {
                    await _inner.DisposeAsync();
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _failure ??= ex;
                    await PublishAsync(size);
                    throw;
                }
                await PublishAsync(size);
            }

            private async ValueTask PublishAsync(long? size)
            {
                var e = _owner.NewEvent(_upload ? FileEventType.Upload : FileEventType.Download, _path) with
                {
                    OpenFlags = _flags,
                    FileSize = size,
                    Elapsed = _owner._time.GetElapsedTime(_start),
                };
                if (_failure != null)
                {
                    await _owner.PublishFailedAsync(e, _failure);
                    return;
                }
                await _owner._events.PublishAsync(e, CancellationToken.None);
                if (_upload && _isNew)
                    await _owner._events.PublishAsync(e with { Type = FileEventType.FirstUpload }, CancellationToken.None);
            }
        }
    }
}
