using System.Buffers;
using Amazon.S3.Model;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.S3;

/// <summary>
/// The streaming upload of one file. The data is buffered up to <see cref="S3StorageOptions.UploadPartSize"/>. A file
/// that stays smaller is one PutObject at <see cref="CompleteAsync"/>. A larger file is a multipart upload: each full
/// buffer is one UploadPart, up to <see cref="S3StorageOptions.UploadConcurrency"/> parts are sent while the next one fills, and
/// <see cref="CompleteAsync"/> sends the last part and CompleteMultipartUpload. Any failure aborts the multipart upload
/// (AbortMultipartUpload), so no object and no stored parts stay; the upload then fails every later call.
/// </summary>
internal sealed class S3Upload : IDisposable
{
    /// <summary>The most parts of one multipart upload in S3.</summary>
    public const int MaxParts = 10_000;

    private readonly S3ObjectStore _store;
    private readonly string _key;
    private readonly string _path;
    private readonly int _partSize;
    private readonly List<PartETag> _parts = [];
    private readonly Queue<Task<PartETag>> _inFlight = new();
    private readonly CancellationTokenSource _abort = new();
    private byte[]? _buffer;
    private int _count;
    private string? _uploadId;
    private int _nextPartNumber = 1;
    private bool _failed;
    private bool _done;

    public S3Upload(S3ObjectStore store, string key, string path)
    {
        _store = store;
        _key = key;
        _path = path;
        _partSize = store.Options.UploadPartSize;
    }

    /// <summary>The size of the file so far, with the data that is not sent yet.</summary>
    public long Length { get; private set; }

    /// <summary>The id of the multipart upload, or null while the data fits in one PutObject.</summary>
    public string? UploadId => _uploadId;

    /// <summary>
    /// Starts with the content of an existing object, for a write at its end (a resumed upload or an append): a small
    /// object is read into the buffer, a larger one becomes the first parts by a copy on the server (UploadPartCopy).
    /// </summary>
    public Task StartWithAsync(S3ObjectInfo existing, CancellationToken ct) => GuardAsync(async () =>
    {
        if (existing.Size < _partSize)
        {
            var size = (int)existing.Size;
            _buffer = ArrayPool<byte>.Shared.Rent(_partSize);
            await _store.ReadRangeAsync(_key, existing.ETag, 0, _buffer.AsMemory(0, size), ct).ConfigureAwait(false);
            _count = size;
        }
        else
        {
            _uploadId = await _store.InitiateAsync(_key, ct).ConfigureAwait(false);
            var copied = await _store.CopyPartsAsync(_key, existing, _key, _uploadId, _nextPartNumber, ct).ConfigureAwait(false);
            _parts.AddRange(copied);
            _nextPartNumber += copied.Count;
        }
        Length = existing.Size;
    });

    /// <summary>Appends data at <see cref="Length"/>.</summary>
    public Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct) => GuardAsync(async () =>
    {
        while (data.Length > 0)
        {
            _buffer ??= ArrayPool<byte>.Shared.Rent(_partSize);
            var length = Math.Min(data.Length, _partSize - _count);
            data.Span.Slice(0, length).CopyTo(_buffer.AsSpan(_count));
            _count += length;
            Length += length;
            data = data.Slice(length);
            if (_count == _partSize)
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

    /// <summary>Waits until the parts that are sent are stored (fsync). The buffered rest is sent by <see cref="CompleteAsync"/>.</summary>
    public Task FlushAsync(CancellationToken ct) => GuardAsync(async () =>
    {
        while (_inFlight.Count > 0)
            _parts.Add(await _inFlight.Dequeue().WaitAsync(ct).ConfigureAwait(false));
    });

    /// <summary>Stores the object: one PutObject, or the last part and CompleteMultipartUpload.</summary>
    public Task CompleteAsync(CancellationToken ct) => GuardAsync(async () =>
    {
        if (_uploadId == null)
        {
            await _store.PutAsync(_key, _buffer ?? [], _count, ct).ConfigureAwait(false);
        }
        else
        {
            if (_count > 0)
                await SendBufferAsync(ct).ConfigureAwait(false);
            while (_inFlight.Count > 0)
                _parts.Add(await _inFlight.Dequeue().ConfigureAwait(false));
            await _store.CompleteAsync(_key, _uploadId, _parts, ct).ConfigureAwait(false);
        }
        _done = true;
        ReturnBuffer();
    });

    /// <summary>Aborts an unfinished multipart upload and frees the buffers.</summary>
    public async Task AbortAsync()
    {
        if (_done)
            return;
        _done = true;
        _failed = true;
        await _abort.CancelAsync().ConfigureAwait(false);
        while (_inFlight.Count > 0)
        {
            try { await _inFlight.Dequeue().ConfigureAwait(false); }
            catch (Exception) { /* the upload failed or was aborted; the first error is reported */ }
        }
        if (_uploadId != null)
            await _store.AbortAsync(_key, _uploadId).ConfigureAwait(false);
        ReturnBuffer();
    }

    public void Dispose()
    {
        ReturnBuffer();
        _abort.Dispose();
    }

    private async Task SendBufferAsync(CancellationToken ct)
    {
        if (_nextPartNumber > MaxParts)
            throw new FileSystemException(FileSystemError.QuotaExceeded,
                $"The file is larger than the storage accepts ({MaxParts} parts of {_partSize} bytes, see UploadPartSize): {_path}");
        _uploadId ??= await _store.InitiateAsync(_key, ct).ConfigureAwait(false);

        var buffer = _buffer!;
        var count = _count;
        _buffer = null;
        _count = 0;
        _inFlight.Enqueue(SendPartAsync(_uploadId, _nextPartNumber++, buffer, count));
        while (_inFlight.Count > Math.Max(1, _store.Options.UploadConcurrency))
            _parts.Add(await _inFlight.Dequeue().ConfigureAwait(false));
    }

    private async Task<PartETag> SendPartAsync(string uploadId, int partNumber, byte[] buffer, int count)
    {
        try
        {
            return await _store.UploadPartAsync(_key, uploadId, partNumber, buffer, count, _abort.Token).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
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
