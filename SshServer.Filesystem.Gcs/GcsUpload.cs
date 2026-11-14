using System.Buffers;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.Gcs;

/// <summary>
/// The streaming upload of one file. The data is buffered up to <see cref="GcsStorageOptions.UploadChunkSize"/>. A file
/// that stays smaller is one request at <see cref="CompleteAsync"/>. A larger file is a resumable upload: each full
/// buffer is one chunk, sent while the next one fills (one chunk at a time: a resumable upload is sequential), and
/// <see cref="CompleteAsync"/> sends the last chunk, which finalizes the object. Any failure, and
/// <see cref="AbortAsync"/>, cancels the session without finalizing it, so no object appears; the upload then fails every
/// later call.
/// <para>
/// A write at the end of an existing file keeps its data: a small object is read into the buffer; a larger one stays
/// where it is, the new data is uploaded as a temporary object "KEY.part-ID" and joined to it with a compose on the
/// server at <see cref="CompleteAsync"/> (so the temporary object is visible in a listing until then).
/// </para>
/// </summary>
internal sealed class GcsUpload : IDisposable
{
    private readonly GcsObjectStore _store;
    private readonly string _key;
    private readonly string _path;
    private readonly int _chunkSize;
    private readonly bool _createOnly;
    private readonly CancellationTokenSource _abort = new();
    private string _uploadKey;
    private GcsObjectInfo? _composeOnto;
    private Uri? _session;
    private Task? _inFlight;
    private byte[]? _buffer;
    private int _count;
    private long _sent;
    private bool _tempStored;
    private bool _failed;
    private bool _done;

    /// <param name="createOnly">The object must not exist when it is stored (a file that was opened with Create and Exclusive).</param>
    public GcsUpload(GcsObjectStore store, string key, string path, bool createOnly)
    {
        _store = store;
        _key = key;
        _uploadKey = key;
        _path = path;
        _chunkSize = store.Options.UploadChunkSize;
        _createOnly = createOnly;
    }

    /// <summary>The size of the file so far, with the data that is not sent yet.</summary>
    public long Length { get; private set; }

    /// <summary>Starts with the content of an existing object, for a write at its end (a resumed upload or an append).</summary>
    public Task StartWithAsync(GcsObjectInfo existing, CancellationToken ct) => GuardAsync(async () =>
    {
        if (existing.Size < _chunkSize)
        {
            var size = (int)existing.Size;
            _buffer = ArrayPool<byte>.Shared.Rent(_chunkSize);
            await _store.ReadRangeAsync(_key, existing.Generation, 0, _buffer, size, ct).ConfigureAwait(false);
            _count = size;
        }
        else
        {
            _composeOnto = existing;
            _uploadKey = $"{_key}.part-{Guid.NewGuid():N}";
        }
        Length = existing.Size;
    });

    /// <summary>Appends data at <see cref="Length"/>.</summary>
    public Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct) => GuardAsync(async () =>
    {
        while (data.Length > 0)
        {
            _buffer ??= ArrayPool<byte>.Shared.Rent(_chunkSize);
            var length = Math.Min(data.Length, _chunkSize - _count);
            data.Span.Slice(0, length).CopyTo(_buffer.AsSpan(_count));
            _count += length;
            Length += length;
            data = data.Slice(length);
            if (_count == _chunkSize)
                await SendBufferAsync(ct).ConfigureAwait(false);
        }
    });

    /// <summary>
    /// Copies the bytes at <paramref name="offset"/> that are still in the buffer; returns 0 at or past the end, and -1
    /// when the bytes were sent already (an object store cannot read a part of an unfinished upload).
    /// </summary>
    public int Read(long offset, Span<byte> destination)
    {
        ThrowIfFailed();
        if (offset >= Length)
            return 0;
        var bufferStart = Length - _count;
        if (offset < bufferStart || _buffer == null)
            return -1;
        var length = (int)Math.Min(destination.Length, Length - offset);
        _buffer.AsSpan((int)(offset - bufferStart), length).CopyTo(destination);
        return length;
    }

    /// <summary>Waits until the chunks that are sent are stored (fsync). The buffered rest is sent by <see cref="CompleteAsync"/>.</summary>
    public Task FlushAsync(CancellationToken ct) => GuardAsync(async () =>
    {
        if (_inFlight != null)
            await _inFlight.WaitAsync(ct).ConfigureAwait(false);
    });

    /// <summary>Stores the object: one request, or the last chunk (and the compose of an append).</summary>
    public Task CompleteAsync(CancellationToken ct) => GuardAsync(async () =>
    {
        if (_session != null)
        {
            if (_inFlight != null)
                await _inFlight.ConfigureAwait(false);
            await _store.SendChunkAsync(_session, _buffer.AsMemory(0, _count), _sent, _sent + _count, ct).ConfigureAwait(false);
            _tempStored = _composeOnto != null;
        }
        else if (_composeOnto == null)
        {
            await _store.PutAsync(_key, _buffer ?? [], _count, _createOnly, ct).ConfigureAwait(false);
        }
        else if (_count > 0)
        {
            await _store.PutAsync(_uploadKey, _buffer!, _count, createOnly: false, ct).ConfigureAwait(false);
            _tempStored = true;
        }

        if (_composeOnto != null && _tempStored)
        {
            await _store.ComposeAppendAsync(_key, _composeOnto, _uploadKey, ct).ConfigureAwait(false);
            _tempStored = false;
            await DeleteTempAsync().ConfigureAwait(false);
        }
        _done = true;
        ReturnBuffer();
    });

    /// <summary>Cancels an unfinished upload (nothing is finalized) and frees the buffers.</summary>
    public async Task AbortAsync()
    {
        if (_done)
            return;
        _done = true;
        _failed = true;
        await _abort.CancelAsync().ConfigureAwait(false);
        if (_inFlight != null)
        {
            try { await _inFlight.ConfigureAwait(false); }
            catch (Exception) { /* the upload failed or was aborted; the first error is reported */ }
        }
        if (_session != null)
            await _store.CancelUploadAsync(_session).ConfigureAwait(false);
        if (_tempStored)
            await DeleteTempAsync().ConfigureAwait(false);
        ReturnBuffer();
    }

    public void Dispose()
    {
        ReturnBuffer();
        _abort.Dispose();
    }

    private async Task SendBufferAsync(CancellationToken ct)
    {
        _session ??= await _store.InitiateUploadAsync(_uploadKey, _createOnly && _composeOnto == null, ct).ConfigureAwait(false);
        if (_inFlight != null)
            await _inFlight.ConfigureAwait(false); // one chunk at a time; a failure of the previous one is thrown here

        var buffer = _buffer!;
        var count = _count;
        var offset = _sent;
        _buffer = null;
        _count = 0;
        _sent += count;
        _inFlight = SendChunkAsync(_session, buffer, count, offset);
    }

    private async Task SendChunkAsync(Uri session, byte[] buffer, int count, long offset)
    {
        try
        {
            await _store.SendChunkAsync(session, buffer.AsMemory(0, count), offset, total: null, _abort.Token).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async Task DeleteTempAsync()
    {
        try
        {
            await _store.DeleteAsync(_uploadKey, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Best effort: the temporary object is invisible to the content of the file.
        }
    }

    /// <summary>Runs one step; a failure aborts the upload and is thrown.</summary>
    private async Task GuardAsync(Func<Task> step)
    {
        ThrowIfFailed();
        try
        {
            await step().ConfigureAwait(false);
        }
        catch
        {
            await AbortAsync().ConfigureAwait(false);
            throw;
        }
    }

    private void ThrowIfFailed()
    {
        if (_failed)
            throw new FileSystemException(FileSystemError.Failure, $"The upload failed and was aborted: {_path}");
        if (_done)
            throw new FileSystemException(FileSystemError.Failure, $"The file is closed: {_path}");
    }

    private void ReturnBuffer()
    {
        if (_buffer != null)
            ArrayPool<byte>.Shared.Return(_buffer);
        _buffer = null;
        _count = 0;
    }
}
