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
    /// The storage rule "disk quota" (issue #62) for one storage: the own storage of a user or one virtual folder (a
    /// <see cref="QuotaScope"/>). It counts the size and the number of the files in the <see cref="QuotaUsageTracker"/>
    /// and refuses what would go over the <see cref="DiskQuota"/> with <see cref="FileSystemError.QuotaExceeded"/>
    /// (SFTP: SSH_FX_FAILURE "Quota exceeded"). It never scans the storage; the counters are approximate and a scan
    /// (<see cref="QuotaScanService"/>) corrects them.
    /// <list type="bullet">
    /// <item>Open for writing: a new file reserves one file, and a full quota refuses to create it. A truncated file releases
    /// its old size. The check is on every write that makes the file larger, so one large write cannot go over the limit.</item>
    /// <item>A write over the quota fails, and at once the handle is aborted in the storage and the partial file is removed,
    /// so no partial file stays and the counters lose nothing. Every later call of the handle fails too.</item>
    /// <item>A lost session (<see cref="IFileHandle.AbortAsync"/>) counts what the storage kept: a disk keeps the partial
    /// file, an object store keeps nothing (or the old object).</item>
    /// <item>Delete releases the file, a rename that replaces a file releases the replaced file, a size change by SETSTAT
    /// is checked and counted. Directories are not counted.</item>
    /// <item><see cref="GetStorageSpaceAsync"/> reports the quota as the size of the storage, so <c>df</c> shows it.</item>
    /// </list>
    /// The factory wraps each storage (below the mount routing), so a rename between two quota scopes cannot happen:
    /// <c>MountedFileSystem</c> refuses a rename between two storages.
    /// </summary>
    public sealed class DiskQuotaFileSystem : IFileSystem
    {
        private const FileOpenFlags WriteFlags = FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate | FileOpenFlags.Append;

        private readonly IFileSystem _inner;
        private readonly QuotaUsageTracker _tracker;
        private readonly QuotaScope _scope;
        private readonly DiskQuota _limit;

        public DiskQuotaFileSystem(IFileSystem inner, QuotaUsageTracker tracker, QuotaScope scope, DiskQuota limit)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
            _scope = scope;
            _limit = limit ?? throw new ArgumentNullException(nameof(limit));
        }

        /// <summary>The decorator around <paramref name="inner"/>, or <paramref name="inner"/> itself without a limit.</summary>
        public static IFileSystem Wrap(IFileSystem inner, QuotaUsageTracker tracker, QuotaScope scope, DiskQuota? limit)
            => DiskQuota.OrNull(limit) is { } quota ? new DiskQuotaFileSystem(inner, tracker, scope, quota) : inner;

        public StorageCapabilities Capabilities => _inner.Capabilities;

        public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct) => _inner.StatAsync(path, followLinks, ct);

        public IAsyncEnumerable<FileSystemEntry> ListAsync(string path, CancellationToken ct) => _inner.ListAsync(path, ct);

        public async ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct)
        {
            if ((flags & WriteFlags) == 0)
                return await _inner.OpenAsync(path, flags, initial, ct);

            var before = await _inner.StatAsync(path, followLinks: true, ct);
            var existing = before is { Type: FileSystemEntryType.File } ? before : null;
            var truncates = existing != null && (flags & FileOpenFlags.Truncate) != 0;
            var creates = before is null && (flags & FileOpenFlags.Create) != 0;

            if (creates && ((_limit.MaxSizeBytes > 0 && _tracker.Current(_scope).UsedBytes >= _limit.MaxSizeBytes)
                            || !_tracker.TryReserveDisk(_scope, _limit, 0, 1)))
                throw Exceeded(path);

            IFileHandle handle;
            try
            {
                handle = await _inner.OpenAsync(path, flags, initial, ct);
            }
            catch
            {
                if (creates)
                    _tracker.AddDisk(_scope, 0, -1);
                throw;
            }

            if (truncates)
                _tracker.AddDisk(_scope, -existing!.Size, 0);
            var size = truncates ? 0 : existing?.Size ?? 0;
            return new Handle(this, handle, path, size, (flags & FileOpenFlags.Append) != 0);
        }

        public ValueTask CreateDirectoryAsync(string path, CancellationToken ct) => _inner.CreateDirectoryAsync(path, ct);

        public async ValueTask DeleteFileAsync(string path, CancellationToken ct)
        {
            var before = await _inner.StatAsync(path, followLinks: false, ct);
            await _inner.DeleteFileAsync(path, ct);
            if (before is { Type: FileSystemEntryType.File })
                _tracker.AddDisk(_scope, -before.Size, -1);
        }

        public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct) => _inner.DeleteDirectoryAsync(path, ct);

        public async ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct)
        {
            if ((flags & RenameFlags.ReplaceExisting) == 0 || VirtualPath.Normalize(oldPath) == VirtualPath.Normalize(newPath))
            {
                await _inner.RenameAsync(oldPath, newPath, flags, ct);
                return;
            }
            var replaced = await _inner.StatAsync(newPath, followLinks: false, ct);
            await _inner.RenameAsync(oldPath, newPath, flags, ct);
            if (replaced is { Type: FileSystemEntryType.File })
                _tracker.AddDisk(_scope, -replaced.Size, -1);
        }

        public async ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct)
        {
            if (update.Size is not { } size)
            {
                await _inner.SetAttributesAsync(path, update, ct);
                return;
            }
            var before = await _inner.StatAsync(path, followLinks: true, ct);
            var delta = before is { Type: FileSystemEntryType.File } ? size - before.Size : 0;
            await ChangeSizeAsync(path, delta, () => _inner.SetAttributesAsync(path, update, ct));
        }

        public async ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct)
        {
            var space = await _inner.GetStorageSpaceAsync(path, ct);
            if (_limit.MaxSizeBytes <= 0)
                return space;
            var total = (ulong)_limit.MaxSizeBytes;
            var free = (ulong)Math.Max(0, _limit.MaxSizeBytes - _tracker.Current(_scope).UsedBytes);
            return new StorageSpace(total, free, space is null ? free : Math.Min(free, space.AvailableBytes));
        }

        /// <summary>Runs a size change: a growth is reserved first (or refused), a shrink is released after it.</summary>
        private async ValueTask ChangeSizeAsync(string path, long delta, Func<ValueTask> change)
        {
            if (delta > 0 && !_tracker.TryReserveDisk(_scope, _limit, delta, 0))
                throw Exceeded(path);
            try
            {
                await change();
            }
            catch
            {
                if (delta > 0)
                    _tracker.AddDisk(_scope, -delta, 0);
                throw;
            }
            if (delta < 0)
                _tracker.AddDisk(_scope, delta, 0);
        }

        private static FileSystemException Exceeded(string path)
            => new(FileSystemError.QuotaExceeded, $"Quota exceeded: {VirtualPath.Normalize(path)}");

        /// <summary>
        /// An open file: it knows the size that is counted for the file (<see cref="_size"/>) and reserves each growth. The
        /// first refused write drops the file at once (a client does not always close a handle after a failed write).
        /// </summary>
        private sealed class Handle : IFileHandle
        {
            private readonly DiskQuotaFileSystem _owner;
            private readonly IFileHandle _inner;
            private readonly string _path;
            private readonly bool _append;
            private readonly object _lock = new();
            private long _size;
            private bool _exceeded; // a write was refused: the file is dropped and the storage handle is closed
            private bool _closed;

            public Handle(DiskQuotaFileSystem owner, IFileHandle inner, string path, long size, bool append)
            {
                _owner = owner;
                _inner = inner;
                _path = path;
                _size = size;
                _append = append;
            }

            private QuotaUsageTracker Tracker => _owner._tracker;

            public ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken ct)
            {
                ThrowIfExceeded();
                return _inner.ReadAsync(offset, buffer, ct);
            }

            public async ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct)
            {
                long growth = 0;
                var drop = false;
                lock (_lock)
                {
                    if (_exceeded)
                        throw Exceeded(_path);
                    if (!_closed) // a closed handle: the storage refuses the write
                    {
                        var end = (_append ? _size : offset) + data.Length;
                        growth = Math.Max(0, end - _size);
                        if (growth > 0 && !Tracker.TryReserveDisk(_owner._scope, _owner._limit, growth, 0))
                            _exceeded = _closed = drop = true;
                        else
                            _size += growth;
                    }
                }
                if (drop)
                {
                    await DropAsync();
                    throw Exceeded(_path);
                }
                try
                {
                    await _inner.WriteAsync(offset, data, ct);
                }
                catch
                {
                    lock (_lock)
                        _size -= growth;
                    Tracker.AddDisk(_owner._scope, -growth, 0);
                    throw;
                }
            }

            public ValueTask FlushAsync(CancellationToken ct)
            {
                ThrowIfExceeded();
                return _inner.FlushAsync(ct);
            }

            public ValueTask<FileSystemEntry> StatAsync(CancellationToken ct)
            {
                ThrowIfExceeded();
                return _inner.StatAsync(ct);
            }

            public async ValueTask SetAttributesAsync(FileAttributesUpdate update, CancellationToken ct)
            {
                ThrowIfExceeded();
                if (update.Size is not { } size)
                {
                    await _inner.SetAttributesAsync(update, ct);
                    return;
                }
                long delta;
                lock (_lock)
                    delta = size - _size;
                await _owner.ChangeSizeAsync(_path, delta, () => _inner.SetAttributesAsync(update, ct));
                lock (_lock)
                    _size = size;
            }

            public ValueTask DisposeAsync() => CloseAsync(abort: false);

            public ValueTask AbortAsync() => CloseAsync(abort: true);

            private void ThrowIfExceeded()
            {
                lock (_lock)
                {
                    if (_exceeded)
                        throw Exceeded(_path);
                }
            }

            private async ValueTask CloseAsync(bool abort)
            {
                lock (_lock)
                {
                    if (_closed)
                        return; // closed before, or dropped after a refused write
                    _closed = true;
                }
                if (!abort)
                {
                    await _inner.DisposeAsync();
                    return;
                }
                // The session was lost: count what the storage kept (a disk keeps the partial file, an object store nothing).
                await _inner.AbortAsync();
                Reconcile(await StatQuietlyAsync());
            }

            /// <summary>Drops the file of a refused upload: the storage aborts it, and the partial file of this handle is removed.</summary>
            private async ValueTask DropAsync()
            {
                await _inner.AbortAsync();
                var after = await StatQuietlyAsync();
                // Remove only the partial file of this handle: an object store keeps the old object, which has another size.
                if (after is { Type: FileSystemEntryType.File } && after.Size == _size)
                {
                    try
                    {
                        await _owner._inner.DeleteFileAsync(_path, CancellationToken.None);
                        after = null;
                    }
                    catch (FileSystemException)
                    {
                        // It stays, and it stays counted.
                    }
                }
                Reconcile(after);
            }

            /// <summary>Changes the counters from what this handle counted to what the storage has now.</summary>
            private void Reconcile(FileSystemEntry? after)
                => Tracker.AddDisk(_owner._scope, (after?.Size ?? 0) - _size, after is null ? -1 : 0);

            private async ValueTask<FileSystemEntry?> StatQuietlyAsync()
            {
                try
                {
                    var entry = await _owner._inner.StatAsync(_path, followLinks: true, CancellationToken.None);
                    return entry is { Type: FileSystemEntryType.File } ? entry : null;
                }
                catch (FileSystemException)
                {
                    // Unknown: keep what is counted.
                    return new FileSystemEntry(VirtualPath.GetName(VirtualPath.Normalize(_path)), FileSystemEntryType.File, _size, default, default);
                }
            }
        }
    }
}
