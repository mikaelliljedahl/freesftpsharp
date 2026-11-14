using System.Security.Cryptography;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.Encrypted;

/// <summary>
/// An open file of <see cref="EncryptedFileSystem"/>. A writing handle keeps the last, incomplete chunk in memory and
/// writes every complete chunk at once; the last chunk is written when the handle is closed. A reading handle decrypts
/// the chunk of the requested offset and keeps the last decrypted chunk for the next read.
/// </summary>
internal sealed class EncryptedFileHandle : IFileHandle
{
    private readonly IFileHandle _inner;
    private readonly ChunkCipher? _cipher;
    private readonly string _path;
    private readonly FileOpenFlags _flags;
    private readonly bool _writing;

    /// <summary>Reading: the plaintext size of the file. Writing: the bytes written so far.</summary>
    private long _size;

    /// <summary>Writing: the chunks that are on the storage; the plaintext after them is in <see cref="_tail"/>.</summary>
    private long _writtenChunks;
    private readonly byte[]? _tail;
    private int _tailLength;
    private FileAttributesUpdate? _times;

    private long _cachedChunk = -1;
    private byte[]? _cache;
    private int _cacheLength;
    private bool _disposed;

    public EncryptedFileHandle(IFileHandle inner, ChunkCipher? cipher, string path, FileOpenFlags flags, long size, bool writing)
    {
        _inner = inner;
        _cipher = cipher;
        _path = path;
        _flags = flags;
        _size = size;
        _writing = writing;
        if (writing)
            _tail = new byte[EncryptedFileFormat.ChunkSize];
    }

    public async ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Check(FileOpenFlags.Read);
        if (offset < 0)
            throw new FileSystemException(FileSystemError.Failure, $"Negative offset: {_path}");

        var total = 0;
        while (total < buffer.Length && offset + total < _size)
        {
            var position = offset + total;
            var index = position / EncryptedFileFormat.ChunkSize;
            var within = (int)(position % EncryptedFileFormat.ChunkSize);
            var chunk = await GetChunkAsync(index, ct);
            var count = Math.Min(chunk.Length - within, buffer.Length - total);
            if (count <= 0)
                break;
            chunk.Span.Slice(within, count).CopyTo(buffer.Span[total..]);
            total += count;
        }
        return total;
    }

    public async ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Check(FileOpenFlags.Write);
        if (!_writing)
            throw new FileSystemException(FileSystemError.OpNotSupported, $"The encrypted storage cannot change an existing file; write it again with truncate: {_path}");
        if (offset != _size)
            throw new FileSystemException(FileSystemError.OpNotSupported, $"The encrypted storage writes a file only sequentially (offset {offset}, size {_size}): {_path}");

        while (!data.IsEmpty)
        {
            var count = Math.Min(data.Length, EncryptedFileFormat.ChunkSize - _tailLength);
            data.Span[..count].CopyTo(_tail.AsSpan(_tailLength));
            _tailLength += count;
            _size += count;
            data = data[count..];
            if (_tailLength == EncryptedFileFormat.ChunkSize)
                await WriteChunkAsync(ct);
        }
    }

    /// <summary>
    /// Writes the complete chunks to stable storage. The last, incomplete chunk stays in memory until the close: writing it
    /// now and again later would encrypt two plaintexts with the same nonce.
    /// </summary>
    public ValueTask FlushAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Check(FileOpenFlags.None);
        return _inner.FlushAsync(ct);
    }

    public async ValueTask<FileSystemEntry> StatAsync(CancellationToken ct)
    {
        Check(FileOpenFlags.None);
        var entry = await _inner.StatAsync(ct);
        return entry with { Size = _writing ? _size : EncryptedFileFormat.DisplaySize(entry.Size) };
    }

    public async ValueTask SetAttributesAsync(FileAttributesUpdate update, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Check(FileOpenFlags.None);
        if (update.Size != null)
            throw new FileSystemException(FileSystemError.OpNotSupported, $"The encrypted storage cannot change the size of a file: {_path}");
        await _inner.SetAttributesAsync(update, ct);
        // The last chunk is written at the close and changes the write time again, so the times are set again then.
        if (_writing && update.HasTimes)
            _times = new FileAttributesUpdate { LastAccessTimeUtc = update.LastAccessTimeUtc ?? _times?.LastAccessTimeUtc, LastWriteTimeUtc = update.LastWriteTimeUtc ?? _times?.LastWriteTimeUtc };
    }

    /// <summary>Writes the last chunk (also an empty one, it marks the end of the file) and closes the file.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;
        _disposed = true;

        try
        {
            if (_writing)
            {
                await WriteChunkAsync(CancellationToken.None);
                if (_times != null)
                    await _inner.SetAttributesAsync(_times, CancellationToken.None);
            }
        }
        finally
        {
            try
            {
                await _inner.DisposeAsync();
            }
            finally
            {
                _cipher?.Dispose();
                if (_tail != null)
                    CryptographicOperations.ZeroMemory(_tail);
                if (_cache != null)
                    CryptographicOperations.ZeroMemory(_cache);
            }
        }
    }

    /// <summary>Encrypts the tail as the next chunk and writes it.</summary>
    private async ValueTask WriteChunkAsync(CancellationToken ct)
    {
        if (_writtenChunks >= EncryptedFileFormat.MaxChunkCount)
            throw new FileSystemException(FileSystemError.Failure, $"The file is too large for the encrypted storage: {_path}");
        var encrypted = new byte[_tailLength + EncryptedFileFormat.TagSize];
        _cipher!.Encrypt(_writtenChunks, _tail.AsSpan(0, _tailLength), encrypted);
        await _inner.WriteAsync(EncryptedFileFormat.ChunkOffset(_writtenChunks), encrypted, ct);
        _writtenChunks++;
        _tailLength = 0;
    }

    /// <summary>The plaintext of chunk <paramref name="index"/>; it must be inside the file.</summary>
    private async ValueTask<ReadOnlyMemory<byte>> GetChunkAsync(long index, CancellationToken ct)
    {
        if (_writing && index == _writtenChunks)
            return _tail.AsMemory(0, _tailLength);
        if (index == _cachedChunk)
            return _cache.AsMemory(0, _cacheLength);

        // Every chunk before the last one is full; the last one of a complete file is shorter.
        var lastIndex = _writing ? _writtenChunks - 1 : _size / EncryptedFileFormat.ChunkSize;
        var plaintextLength = index < lastIndex || _writing ? EncryptedFileFormat.ChunkSize : (int)(_size % EncryptedFileFormat.ChunkSize);
        var encrypted = new byte[plaintextLength + EncryptedFileFormat.TagSize];
        var offset = EncryptedFileFormat.ChunkOffset(index);
        var read = 0;
        while (read < encrypted.Length)
        {
            var n = await _inner.ReadAsync(offset + read, encrypted.AsMemory(read), ct);
            if (n == 0)
                throw EncryptedFileSystem.Damaged(_path, $"chunk {index} is cut");
            read += n;
        }

        _cache ??= new byte[EncryptedFileFormat.ChunkSize];
        _cachedChunk = -1;
        try
        {
            _cipher!.Decrypt(index, encrypted, _cache);
        }
        catch (CryptographicException ex)
        {
            CryptographicOperations.ZeroMemory(_cache);
            throw EncryptedFileSystem.Damaged(_path, $"chunk {index} does not authenticate", ex);
        }
        _cachedChunk = index;
        _cacheLength = plaintextLength;
        return _cache.AsMemory(0, _cacheLength);
    }

    private void Check(FileOpenFlags access)
    {
        if (_disposed)
            throw new FileSystemException(FileSystemError.Failure, $"The file is closed: {_path}");
        if ((_flags & access) != access)
            throw new FileSystemException(FileSystemError.PermissionDenied, $"The file is not open for {access}: {_path}");
    }
}
