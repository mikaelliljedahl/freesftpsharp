using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.Encrypted;

/// <summary>
/// Encrypts the file contents of another <see cref="IFileSystem"/> (normally the local disk) with AES-256-GCM and a
/// key per file (<see cref="EncryptedFileFormat"/>). Names, directories, times and permissions stay as they are; the
/// sizes are the plaintext sizes.
/// <para>
/// A file is written once, from the start to the end: a new file, or one opened with
/// <see cref="FileOpenFlags.Truncate"/>. A write at another offset, a write to an existing file, append and a size
/// change throw <see cref="FileSystemError.OpNotSupported"/>, because changing a chunk in place would encrypt new data
/// with a nonce that was used before. A damaged or changed file throws <see cref="FileSystemError.Failure"/>, never
/// gives wrong bytes.
/// </para>
/// </summary>
public sealed class EncryptedFileSystem : IFileSystem
{
    /// <summary>What the format cannot do, whatever the inner storage can.</summary>
    private const StorageCapabilities Unsupported =
        StorageCapabilities.RandomAccessWrite | StorageCapabilities.Append | StorageCapabilities.ServerSideCopy;

    private readonly IFileSystem _inner;
    private readonly IMasterKeyProvider _keys;
    private readonly Action<Span<byte>> _fillSalt;

    public EncryptedFileSystem(IFileSystem inner, IMasterKeyProvider keys)
        : this(inner, keys, RandomNumberGenerator.Fill)
    {
    }

    /// <summary>With a fixed salt for the known-answer tests of the format.</summary>
    internal EncryptedFileSystem(IFileSystem inner, IMasterKeyProvider keys, Action<Span<byte>> fillSalt)
    {
        _inner = inner;
        _keys = keys;
        _fillSalt = fillSalt;
    }

    /// <summary>
    /// The capabilities of the inner storage without <see cref="Unsupported"/>. The names are not encrypted, so
    /// <see cref="StorageCapabilities.CaseInsensitivePaths"/> of the inner storage passes through on purpose: the
    /// permission decorator must compare paths like the disk under it does.
    /// </summary>
    public StorageCapabilities Capabilities => _inner.Capabilities & ~Unsupported;

    public async ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct)
        => ToPlaintext(await _inner.StatAsync(path, followLinks, ct));

    public async IAsyncEnumerable<FileSystemEntry> ListAsync(string path, [EnumeratorCancellation] CancellationToken ct)
    {
        await foreach (var entry in _inner.ListAsync(path, ct))
            yield return ToPlaintext(entry)!;
    }

    public async ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct)
    {
        if ((flags & FileOpenFlags.Append) != 0)
            throw new FileSystemException(FileSystemError.OpNotSupported, $"The encrypted storage cannot append to a file: {path}");

        var create = (flags & FileOpenFlags.Create) != 0;
        var writesNewContent = create
            && ((flags & (FileOpenFlags.Truncate | FileOpenFlags.Exclusive)) != 0 || await _inner.StatAsync(path, true, ct) == null);

        if (!writesNewContent)
        {
            // An existing file: read it, and refuse every write (see the class summary).
            var existing = await _inner.OpenAsync(path, flags, initial, ct);
            try
            {
                var cipher = (flags & FileOpenFlags.Read) != 0 ? await OpenCipherAsync(existing, path, ct) : null;
                var size = cipher == null ? 0 : await ReadablePlaintextSizeAsync(existing, path, ct);
                return new EncryptedFileHandle(existing, cipher, path, flags, size, writing: false);
            }
            catch
            {
                await existing.DisposeAsync();
                throw;
            }
        }

        var key = await GetActiveKeyAsync(ct);
        var salt = new byte[EncryptedFileFormat.SaltSize];
        _fillSalt(salt);
        var header = EncryptedFileFormat.CreateHeader(key.KeyId.Span, salt);

        // Always truncate: a new header has a new salt, so no chunk is ever encrypted twice with the same key and nonce.
        var innerFlags = (flags & (FileOpenFlags.Read | FileOpenFlags.Exclusive)) | FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate;
        var handle = await _inner.OpenAsync(path, innerFlags, initial, ct);
        ChunkCipher? newCipher = null;
        try
        {
            newCipher = new ChunkCipher(key.Key, header);
            await handle.WriteAsync(0, header, ct);
            return new EncryptedFileHandle(handle, newCipher, path, flags, 0, writing: true);
        }
        catch
        {
            newCipher?.Dispose();
            await handle.DisposeAsync();
            throw;
        }
    }

    public ValueTask CreateDirectoryAsync(string path, CancellationToken ct) => _inner.CreateDirectoryAsync(path, ct);

    public ValueTask DeleteFileAsync(string path, CancellationToken ct) => _inner.DeleteFileAsync(path, ct);

    public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct) => _inner.DeleteDirectoryAsync(path, ct);

    /// <summary>The file key does not depend on the path, so a rename moves the encrypted file as it is.</summary>
    public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct) => _inner.RenameAsync(oldPath, newPath, flags, ct);

    public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct)
    {
        if (update.Size != null)
            throw new FileSystemException(FileSystemError.OpNotSupported, $"The encrypted storage cannot change the size of a file: {path}");
        return _inner.SetAttributesAsync(path, update, ct);
    }

    public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct) => _inner.GetStorageSpaceAsync(path, ct);

    private static FileSystemEntry? ToPlaintext(FileSystemEntry? entry)
        => entry is { Type: FileSystemEntryType.File } file ? file with { Size = EncryptedFileFormat.DisplaySize(file.Size) } : entry;

    /// <summary>Reads and checks the header of an existing file and finds its key.</summary>
    private async ValueTask<ChunkCipher> OpenCipherAsync(IFileHandle handle, string path, CancellationToken ct)
    {
        var header = new byte[EncryptedFileFormat.HeaderSize];
        var read = 0;
        while (read < header.Length)
        {
            var n = await handle.ReadAsync(read, header.AsMemory(read), ct);
            if (n == 0)
                break;
            read += n;
        }

        var parsed = read == header.Length ? EncryptedFileFormat.ParseHeader(header) : null;
        if (parsed == null)
            throw Damaged(path, "it has no valid header");

        MasterKey? key;
        try
        {
            key = await _keys.FindKeyAsync(parsed.Value.KeyId, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new FileSystemException(FileSystemError.Failure, $"The encryption key of the file is not available: {path}", ex);
        }
        if (key == null)
            throw new FileSystemException(FileSystemError.Failure, $"The file is encrypted with a key that is not configured: {path}");
        return new ChunkCipher(key.Key, header);
    }

    private static async ValueTask<long> ReadablePlaintextSizeAsync(IFileHandle handle, string path, CancellationToken ct)
    {
        var fileSize = (await handle.StatAsync(ct)).Size;
        return EncryptedFileFormat.PlaintextSize(fileSize) ?? throw Damaged(path, "it is incomplete or was cut");
    }

    private async ValueTask<MasterKey> GetActiveKeyAsync(CancellationToken ct)
    {
        try
        {
            return await _keys.GetActiveKeyAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new FileSystemException(FileSystemError.Failure, "The active encryption key is not available.", ex);
        }
    }

    internal static FileSystemException Damaged(string path, string reason, Exception? inner = null)
        => new(FileSystemError.Failure, $"The encrypted file is damaged or was changed ({reason}): {path}", inner);
}
