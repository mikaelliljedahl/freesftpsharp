using System.Buffers;
using Azure;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.AzureBlob;

/// <summary>
/// The streaming upload of one file. The data is buffered up to <see cref="AzureBlobStorageOptions.UploadBlockSize"/>. A
/// file that stays smaller is one Put Blob at <see cref="CompleteAsync"/>. A larger file is a block blob: each full
/// buffer is one Put Block, up to <see cref="AzureBlobStorageOptions.UploadConcurrency"/> blocks are sent while the next
/// one fills, and <see cref="CompleteAsync"/> sends the last block and Put Block List. The blob appears only at that
/// commit; before it the blocks are uncommitted and invisible, and Azure removes them after a week. So an aborted or
/// failed upload needs no request: it just never commits. Any failure marks the upload as failed (it fails every later call).
/// </summary>
internal sealed class AzureBlobUpload : IDisposable
{
    private readonly AzureBlobStore _store;
    private readonly string _name;
    private readonly string _path;
    private readonly int _blockSize;
    private readonly string _nonce = Guid.NewGuid().ToString("N").Substring(0, 8);
    private readonly List<string> _blockIds = [];
    private readonly Queue<Task> _inFlight = new();
    private readonly CancellationTokenSource _abort = new();
    private byte[]? _buffer;
    private int _count;
    private int _nextBlockNumber;
    private ETag? _ifMatch;
    private bool _failed;
    private bool _done;

    public AzureBlobUpload(AzureBlobStore store, string name, string path)
    {
        _store = store;
        _name = name;
        _path = path;
        _blockSize = store.Options.UploadBlockSize;
    }

    /// <summary>The size of the file so far, with the data that is not sent yet.</summary>
    public long Length { get; private set; }

    /// <summary>The number of blocks that are staged or committed so far (not the buffered rest).</summary>
    public int BlockCount => _blockIds.Count;

    /// <summary>
    /// Starts with the content of an existing blob, for a write at its end (a resumed upload or an append). A blob of
    /// blocks of this server keeps its blocks: nothing is read or sent again. Any other blob is read through the server
    /// and staged as new blocks (the commit then fails with 412 if another writer changed the blob meanwhile).
    /// </summary>
    public Task StartWithAsync(BlobInfo existing, CancellationToken ct) => GuardAsync(async () =>
    {
        _ifMatch = existing.ETag;
        if (existing.Size >= _blockSize)
        {
            var blocks = await _store.CommittedBlocksAsync(_name, ct).ConfigureAwait(false);
            if (blocks.Count > 0 && blocks.Count < AzureBlobStore.MaxBlocks && blocks.Sum(b => b.SizeLong) == existing.Size
                && blocks.All(b => b.Name.Length == AzureBlobStore.BlockIdLength))
            {
                _blockIds.AddRange(blocks.Select(b => b.Name));
                _nextBlockNumber = blocks.Count;
                Length = existing.Size;
                return;
            }
        }

        // Read the blob in blocks: the last, partial one stays in the buffer for the next write.
        for (long offset = 0; offset < existing.Size;)
        {
            _buffer ??= ArrayPool<byte>.Shared.Rent(_blockSize);
            var length = (int)Math.Min(_blockSize - _count, existing.Size - offset);
            await _store.ReadRangeAsync(_name, existing.ETag, offset, _buffer.AsMemory(_count, length), ct).ConfigureAwait(false);
            _count += length;
            Length += length;
            offset += length;
            if (_count == _blockSize)
                await SendBufferAsync(ct).ConfigureAwait(false);
        }
    });

    /// <summary>Appends data at <see cref="Length"/>.</summary>
    public Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct) => GuardAsync(async () =>
    {
        while (data.Length > 0)
        {
            _buffer ??= ArrayPool<byte>.Shared.Rent(_blockSize);
            var length = Math.Min(data.Length, _blockSize - _count);
            data.Span.Slice(0, length).CopyTo(_buffer.AsSpan(_count));
            _count += length;
            Length += length;
            data = data.Slice(length);
            if (_count == _blockSize)
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

    /// <summary>Waits until the blocks that are sent are stored (fsync). The buffered rest is sent by <see cref="CompleteAsync"/>.</summary>
    public Task FlushAsync(CancellationToken ct) => GuardAsync(async () =>
    {
        while (_inFlight.Count > 0)
            await _inFlight.Dequeue().WaitAsync(ct).ConfigureAwait(false);
    });

    /// <summary>Stores the blob: one Put Blob, or the last block and Put Block List.</summary>
    public Task CompleteAsync(CancellationToken ct) => GuardAsync(async () =>
    {
        if (_blockIds.Count == 0)
        {
            await _store.PutAsync(_name, _buffer ?? [], _count, folderMarker: false, ct).ConfigureAwait(false);
        }
        else
        {
            if (_count > 0)
                await SendBufferAsync(ct).ConfigureAwait(false);
            while (_inFlight.Count > 0)
                await _inFlight.Dequeue().ConfigureAwait(false);
            await _store.CommitAsync(_name, _blockIds, _ifMatch, ct).ConfigureAwait(false);
        }
        _done = true;
        ReturnBuffer();
    });

    /// <summary>
    /// Gives up the upload: nothing is committed, so no blob changes. The staged blocks stay uncommitted and invisible;
    /// Azure removes them after a week.
    /// </summary>
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
        ReturnBuffer();
    }

    public void Dispose()
    {
        ReturnBuffer();
        _abort.Dispose();
    }

    private async Task SendBufferAsync(CancellationToken ct)
    {
        if (_nextBlockNumber >= AzureBlobStore.MaxBlocks)
            throw new FileSystemException(FileSystemError.QuotaExceeded,
                $"The file is larger than the storage accepts ({AzureBlobStore.MaxBlocks} blocks of {_blockSize} bytes, see UploadBlockSize): {_path}");

        var buffer = _buffer!;
        var count = _count;
        _buffer = null;
        _count = 0;
        var id = AzureBlobStore.BlockId(_nonce, _nextBlockNumber++);
        _blockIds.Add(id);
        _inFlight.Enqueue(SendBlockAsync(id, buffer, count));
        while (_inFlight.Count > Math.Max(1, _store.Options.UploadConcurrency))
            await _inFlight.Dequeue().ConfigureAwait(false);
    }

    private async Task SendBlockAsync(string id, byte[] buffer, int count)
    {
        try
        {
            await _store.StageBlockAsync(_name, id, buffer, count, _abort.Token).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>Runs one step; a failure gives up the upload and is thrown.</summary>
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
