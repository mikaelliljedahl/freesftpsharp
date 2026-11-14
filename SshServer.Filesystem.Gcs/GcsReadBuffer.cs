using System.Buffers;

namespace SshServer.Filesystem.Gcs;

/// <summary>
/// The read-ahead buffer of an open file: a read outside the buffer fetches <see cref="GcsStorageOptions.ReadAheadSize"/>
/// bytes (or the size of the read, if it is larger) with one ranged download, so a sequential download of 32 KiB SFTP
/// reads is one request per read-ahead size. Every request asks for the generation of the open, so a file that another writer
/// replaces gives a failure instead of mixed content.
/// </summary>
internal sealed class GcsReadBuffer : IDisposable
{
    private readonly GcsObjectStore _store;
    private readonly string _key;
    private readonly GcsObjectInfo _object;
    private byte[]? _buffer;
    private long _start;
    private int _count;

    public GcsReadBuffer(GcsObjectStore store, string key, GcsObjectInfo obj)
    {
        _store = store;
        _key = key;
        _object = obj;
    }

    public async ValueTask<int> ReadAsync(long offset, Memory<byte> destination, CancellationToken ct)
    {
        if (offset >= _object.Size || destination.Length == 0)
            return 0;
        if (_buffer == null || offset < _start || offset >= _start + _count)
            await FillAsync(offset, destination.Length, ct).ConfigureAwait(false);

        var available = (int)Math.Min(destination.Length, _start + _count - offset);
        _buffer.AsSpan((int)(offset - _start), available).CopyTo(destination.Span);
        return available;
    }

    /// <summary>Fetches the bytes from <paramref name="offset"/>: at least <paramref name="minimum"/>, at most to the end of the file.</summary>
    public async Task FillAsync(long offset, int minimum, CancellationToken ct)
    {
        if (offset >= _object.Size)
            return;
        var length = (int)Math.Min(Math.Max(_store.Options.ReadAheadSize, minimum), _object.Size - offset);
        if (_buffer == null || _buffer.Length < length)
        {
            ReturnBuffer();
            _buffer = ArrayPool<byte>.Shared.Rent(length);
        }

        _count = 0; // the buffer is not valid while it is filled
        await _store.ReadRangeAsync(_key, _object.Generation, offset, _buffer, length, ct).ConfigureAwait(false);
        _start = offset;
        _count = length;
    }

    public void Dispose() => ReturnBuffer();

    private void ReturnBuffer()
    {
        if (_buffer != null)
            ArrayPool<byte>.Shared.Return(_buffer);
        _buffer = null;
        _count = 0;
    }
}
