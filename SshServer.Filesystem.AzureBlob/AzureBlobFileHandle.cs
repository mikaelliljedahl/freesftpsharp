using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.AzureBlob;

/// <summary>
/// An open file of <see cref="AzureBlobFileSystem"/>. Until the first write, reads go to the blob of the open (through a
/// <see cref="AzureBlobReadBuffer"/>); the first write starts an <see cref="AzureBlobUpload"/>, and reads then see only the data
/// that is not sent yet. Writes are sequential: only a write at the current end of the file is accepted. The blob
/// changes only at <see cref="DisposeAsync"/>: the upload is completed, or a new or truncated file is stored empty.
/// <see cref="AbortAsync"/> drops the upload instead and the blob stays as it was.
/// <para>
/// The operations of one handle run one after the other: the SFTP engine can close the handles of a lost session from
/// another thread while a request of that session still runs, and the buffers must not be freed under a running write.
/// </para>
/// </summary>
internal sealed class AzureBlobFileHandle : IFileHandle
{
    private readonly AzureBlobStore _store;
    private readonly string _key;
    private readonly string _path;
    private readonly FileOpenFlags _flags;
    private readonly BlobInfo? _existing;
    private readonly DateTime _openedUtc = DateTime.UtcNow;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private AzureBlobReadBuffer? _reader;
    private AzureBlobUpload? _upload;
    private bool _disposed;

    /// <param name="existing">The blob to read and to keep; null for a new file or a truncated one.</param>
    public AzureBlobFileHandle(AzureBlobStore store, string key, string path, FileOpenFlags flags, BlobInfo? existing)
    {
        _store = store;
        _key = key;
        _path = path;
        _flags = flags;
        _existing = existing;
        if (existing != null && (flags & FileOpenFlags.Read) != 0)
            _reader = new AzureBlobReadBuffer(store, key, existing);
    }

    private long Length => _upload?.Length ?? _existing?.Size ?? 0;

    /// <summary>
    /// Fetches the first read-ahead block at the open. A file of at most <see cref="AzureBlobStorageOptions.ReadAheadSize"/>
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
                var upload = new AzureBlobUpload(_store, _key, _path);
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
            AzureBlobFileSystem.RequireNoChange(update, Length, _path);
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
            await AzureBlobErrors.RunAsync(_path, async () =>
            {
                if (_upload != null)
                    await _upload.CompleteAsync(CancellationToken.None).ConfigureAwait(false);
                else if (_existing == null)
                    await _store.PutAsync(_key, [], 0, folderMarker: false, CancellationToken.None).ConfigureAwait(false); // a new or truncated file
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
    /// Drops the unfinished upload: no block list is committed, so the blob stays as it was (or is not created). The
    /// staged blocks stay uncommitted and invisible, and Azure removes them after a week.
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

    /// <summary>Runs one operation alone on this handle, checks the access again inside, and translates the Azure errors.</summary>
    private async Task<T> RunAsync<T>(Func<Task<T>> operation, FileOpenFlags access, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Check(access); // the handle can be closed while this call waited
            return await AzureBlobErrors.RunAsync(_path, operation, ct).ConfigureAwait(false);
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
