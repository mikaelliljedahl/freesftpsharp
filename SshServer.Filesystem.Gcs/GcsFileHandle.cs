using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.Gcs;

/// <summary>
/// An open file of <see cref="GcsFileSystem"/>. Until the first write, reads go to the object of the open (through a
/// <see cref="GcsReadBuffer"/>); the first write starts an <see cref="GcsUpload"/>, and reads then see only the data
/// that is not sent yet. Writes are sequential: only a write at the current end of the file is accepted. The object
/// changes only at <see cref="DisposeAsync"/>: the upload is completed, or a new or truncated file is stored empty;
/// <see cref="AbortAsync"/> stores nothing.
/// <para>
/// The operations of one handle run one after the other: the SFTP engine can close the handles of a lost session from
/// another thread while a request of that session still runs, and the buffers must not be freed under a running write.
/// </para>
/// </summary>
internal sealed class GcsFileHandle : IFileHandle
{
    private readonly GcsObjectStore _store;
    private readonly string _key;
    private readonly string _path;
    private readonly FileOpenFlags _flags;
    private readonly GcsObjectInfo? _existing;
    private readonly bool _createOnly;
    private readonly DateTime _openedUtc = DateTime.UtcNow;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private GcsReadBuffer? _reader;
    private GcsUpload? _upload;
    private bool _disposed;

    /// <param name="existing">The object to read and to keep; null for a new file or a truncated one.</param>
    /// <param name="createOnly">A new file that was opened with Exclusive: the object must not exist when it is stored.</param>
    public GcsFileHandle(GcsObjectStore store, string key, string path, FileOpenFlags flags, GcsObjectInfo? existing, bool createOnly)
    {
        _createOnly = createOnly;
        _store = store;
        _key = key;
        _path = path;
        _flags = flags;
        _existing = existing;
        if (existing != null && (flags & FileOpenFlags.Read) != 0)
            _reader = new GcsReadBuffer(store, key, existing);
    }

    private long Length => _upload?.Length ?? _existing?.Size ?? 0;

    /// <summary>
    /// Fetches the first read-ahead block at the open. A file of at most <see cref="GcsStorageOptions.ReadAheadSize"/>
    /// bytes is then read from memory, so it stays readable when it is renamed or removed while it is open, as on a disk.
    /// </summary>
    public Task PrefetchAsync(CancellationToken ct) => _reader?.FillAsync(0, 0, ct) ?? Task.CompletedTask;

    public ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Check(FileOpenFlags.Read);
        return new ValueTask<int>(RunAsync(async () =>
        {
            if (_upload != null)
            {
                var read = _upload.Read(offset, buffer.Span);
                return read >= 0 ? read
                    : throw new FileSystemException(FileSystemError.OpNotSupported, $"The storage cannot read the uploaded part of a file that is open for writing: {_path}");
            }
            return _reader == null ? 0 : await _reader.ReadAsync(offset, buffer, ct).ConfigureAwait(false);
        }, FileOpenFlags.Read, ct));
    }

    public ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Check(FileOpenFlags.Write);
        return new ValueTask(RunAsync(async () =>
        {
            if ((_flags & FileOpenFlags.Append) != 0)
                offset = Length;
            if (offset != Length)
                throw new FileSystemException(FileSystemError.OpNotSupported, $"The storage accepts only sequential writes: {_path}");
            if (data.Length == 0)
                return true;

            if (_upload == null)
            {
                var upload = new GcsUpload(_store, _key, _path, _createOnly);
                if (_existing is { Size: > 0 } existing)
                    await upload.StartWithAsync(existing, ct).ConfigureAwait(false);
                _upload = upload;
                _reader?.Dispose();
                _reader = null;
            }
            await _upload.WriteAsync(data, ct).ConfigureAwait(false);
            return true;
        }, FileOpenFlags.Write, ct));
    }

    public ValueTask FlushAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Check(FileOpenFlags.None);
        return new ValueTask(RunAsync(async () =>
        {
            if (_upload != null)
                await _upload.FlushAsync(ct).ConfigureAwait(false);
            return true;
        }, FileOpenFlags.None, ct));
    }

    public ValueTask<FileSystemEntry> StatAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Check(FileOpenFlags.None);
        return new ValueTask<FileSystemEntry>(RunAsync(() =>
        {
            var written = _upload != null ? DateTime.UtcNow : _existing?.LastModifiedUtc ?? _openedUtc;
            return Task.FromResult(new FileSystemEntry(VirtualPath.GetName(_path), FileSystemEntryType.File, Length, written, written));
        }, FileOpenFlags.None, ct));
    }

    public ValueTask SetAttributesAsync(FileAttributesUpdate update, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Check(FileOpenFlags.None);
        return new ValueTask(RunAsync(() =>
        {
            GcsFileSystem.RequireNoChange(update, Length, _path);
            return Task.FromResult(true);
        }, FileOpenFlags.None, ct));
    }

    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false); // waits for a running operation
        if (_disposed)
        {
            _gate.Release();
            return;
        }
        _disposed = true;

        try
        {
            await GcsErrors.RunAsync(_path, async () =>
            {
                if (_upload != null)
                    await _upload.CompleteAsync(CancellationToken.None).ConfigureAwait(false);
                else if (_existing == null)
                    await _store.PutAsync(_key, [], 0, _createOnly, CancellationToken.None).ConfigureAwait(false); // a new or truncated file
            }, CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            _reader?.Dispose();
            _upload?.Dispose();
            _gate.Release();
        }
    }

    /// <summary>
    /// Closes the handle without storing anything: a resumable upload is cancelled and never finalized, so no object
    /// appears (and a file that was never written is not created). For the close of a lost connection.
    /// </summary>
    public async ValueTask AbortAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false); // waits for a running operation
        if (_disposed)
        {
            _gate.Release();
            return;
        }
        _disposed = true;

        try
        {
            if (_upload != null)
                await _upload.AbortAsync().ConfigureAwait(false);
        }
        finally
        {
            _reader?.Dispose();
            _upload?.Dispose();
            _gate.Release();
        }
    }

    /// <summary>Runs one operation alone on this handle, checks the access again inside, and translates the Gcs errors.</summary>
    private async Task<T> RunAsync<T>(Func<Task<T>> operation, FileOpenFlags access, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Check(access); // the handle can be closed while this call waited
            return await GcsErrors.RunAsync(_path, operation, ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private void Check(FileOpenFlags access)
    {
        if (_disposed)
            throw new FileSystemException(FileSystemError.Failure, $"The file is closed: {_path}");
        if ((_flags & access) != access)
            throw new FileSystemException(FileSystemError.PermissionDenied, $"The file is not open for {access}: {_path}");
    }
}
