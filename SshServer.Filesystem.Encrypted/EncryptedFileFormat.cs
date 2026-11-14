using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SshServer.Filesystem.Encrypted;

/// <summary>
/// The file format v1 of the encrypted storage (docs/ENCRYPTED-STORAGE.md). Do not change it: the known-answer
/// vectors in the tests (EncryptedFileFormatTests) fail when it drifts.
/// <code>
/// header:  "FSS1" | version 0x01 | key id (16 bytes) | file salt (32 bytes, random)          = 53 bytes
/// chunk i: AES-256-GCM(key = fileKey, nonce = salt[0..8] || BE32(i), aad = header || BE32(i))
///          over up to 64 KiB of plaintext, then the 16 byte tag
/// fileKey = HKDF-SHA256(ikm = master key, salt = file salt, info = "freesftpsharp-dare-v1"), 32 bytes, never stored
/// </code>
/// Every chunk except the last has exactly 64 KiB of plaintext; the last chunk always has less (it is empty when the
/// plaintext size is a multiple of 64 KiB). So the plaintext size follows from the file length, and a file that was
/// cut at a chunk boundary (its last chunk is full) or has no chunk is detected as damaged.
/// </summary>
internal static class EncryptedFileFormat
{
    public const byte Version = 1;
    public const int KeyIdSize = 16;
    public const int SaltSize = 32;
    public const int HeaderSize = 4 + 1 + KeyIdSize + SaltSize; // 53
    public const int ChunkSize = 64 * 1024;
    public const int TagSize = 16;
    public const int EncryptedChunkSize = ChunkSize + TagSize;
    public const int NonceSize = 12;
    public const int MasterKeySize = 32;

    /// <summary>The length of the file of an empty plaintext: the header and one empty chunk.</summary>
    public const int MinimumFileSize = HeaderSize + TagSize;

    /// <summary>The chunk index is 4 bytes, so a file has at most 2^32 chunks.</summary>
    public const long MaxChunkCount = 1L << 32;

    private static ReadOnlySpan<byte> Magic => "FSS1"u8;
    private static readonly byte[] HkdfInfo = Encoding.ASCII.GetBytes("freesftpsharp-dare-v1");

    /// <summary>The 16 byte key id in the header of a master key with the configured id: SHA-256(UTF-8 id)[0..16].</summary>
    public static byte[] KeyIdOf(string id) => SHA256.HashData(Encoding.UTF8.GetBytes(id)).AsSpan(0, KeyIdSize).ToArray();

    public static byte[] DeriveFileKey(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> salt)
    {
        var fileKey = new byte[MasterKeySize];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, fileKey, salt, HkdfInfo);
        return fileKey;
    }

    public static byte[] CreateHeader(ReadOnlySpan<byte> keyId, ReadOnlySpan<byte> salt)
    {
        var header = new byte[HeaderSize];
        Magic.CopyTo(header);
        header[4] = Version;
        keyId.CopyTo(header.AsSpan(5, KeyIdSize));
        salt.CopyTo(header.AsSpan(5 + KeyIdSize, SaltSize));
        return header;
    }

    /// <summary>The key id and the salt of a header, or null when it is not a header of version 1.</summary>
    public static (byte[] KeyId, byte[] Salt)? ParseHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length != HeaderSize || !header[..4].SequenceEqual(Magic) || header[4] != Version)
            return null;
        return (header.Slice(5, KeyIdSize).ToArray(), header.Slice(5 + KeyIdSize, SaltSize).ToArray());
    }

    /// <summary>The file length of a plaintext size.</summary>
    public static long FileSize(long plaintextSize)
        => HeaderSize + plaintextSize / ChunkSize * EncryptedChunkSize + plaintextSize % ChunkSize + TagSize;

    /// <summary>
    /// The plaintext size of a file length, or null when no complete file has this length (a cut file, or one that is
    /// still being written).
    /// </summary>
    public static long? PlaintextSize(long fileSize)
    {
        if (fileSize < MinimumFileSize)
            return null;
        var body = fileSize - HeaderSize;
        var last = body % EncryptedChunkSize;
        if (last < TagSize)
            return null;
        return body / EncryptedChunkSize * ChunkSize + last - TagSize;
    }

    /// <summary>
    /// The size to show in a listing: the plaintext size, or for an incomplete file the plaintext of its complete
    /// chunks (for example the progress of an upload).
    /// </summary>
    public static long DisplaySize(long fileSize)
        => PlaintextSize(fileSize) ?? Math.Max(0, fileSize - HeaderSize) / EncryptedChunkSize * ChunkSize;

    /// <summary>The offset of chunk <paramref name="index"/> in the file.</summary>
    public static long ChunkOffset(long index) => HeaderSize + index * EncryptedChunkSize;
}

/// <summary>
/// Encrypts and decrypts the chunks of one file: the file key and the header. Dispose it to clear the file key.
/// </summary>
internal sealed class ChunkCipher : IDisposable
{
    private readonly byte[] _header;
    private readonly byte[] _fileKey;
    private readonly AesGcm _aes;

    public ChunkCipher(ReadOnlySpan<byte> masterKey, byte[] header)
    {
        _header = header;
        var parsed = EncryptedFileFormat.ParseHeader(header) ?? throw new ArgumentException("Not a header of the format v1.", nameof(header));
        _fileKey = EncryptedFileFormat.DeriveFileKey(masterKey, parsed.Salt);
        _aes = new AesGcm(_fileKey, EncryptedFileFormat.TagSize);
    }

    public byte[] Header => _header;

    /// <summary>Encrypts one chunk; <paramref name="output"/> is the plaintext length plus the tag.</summary>
    public void Encrypt(long index, ReadOnlySpan<byte> plaintext, Span<byte> output)
    {
        Span<byte> nonce = stackalloc byte[EncryptedFileFormat.NonceSize];
        Span<byte> aad = stackalloc byte[EncryptedFileFormat.HeaderSize + 4];
        Prepare(index, nonce, aad);
        _aes.Encrypt(nonce, plaintext, output[..plaintext.Length], output.Slice(plaintext.Length, EncryptedFileFormat.TagSize), aad);
    }

    /// <summary>Decrypts one chunk (ciphertext and tag). Throws <see cref="CryptographicException"/> when it was changed.</summary>
    public void Decrypt(long index, ReadOnlySpan<byte> encrypted, Span<byte> plaintext)
    {
        if (encrypted.Length < EncryptedFileFormat.TagSize)
            throw new CryptographicException("The chunk is shorter than its tag.");
        Span<byte> nonce = stackalloc byte[EncryptedFileFormat.NonceSize];
        Span<byte> aad = stackalloc byte[EncryptedFileFormat.HeaderSize + 4];
        Prepare(index, nonce, aad);
        var length = encrypted.Length - EncryptedFileFormat.TagSize;
        _aes.Decrypt(nonce, encrypted[..length], encrypted[length..], plaintext[..length], aad);
    }

    private void Prepare(long index, Span<byte> nonce, Span<byte> aad)
    {
        if (index < 0 || index >= EncryptedFileFormat.MaxChunkCount)
            throw new ArgumentOutOfRangeException(nameof(index));
        // nonce = salt[0..8] || BE32(i); the salt starts after magic, version and key id.
        _header.AsSpan(5 + EncryptedFileFormat.KeyIdSize, 8).CopyTo(nonce);
        BinaryPrimitives.WriteUInt32BigEndian(nonce[8..], (uint)index);
        _header.CopyTo(aad);
        BinaryPrimitives.WriteUInt32BigEndian(aad[EncryptedFileFormat.HeaderSize..], (uint)index);
    }

    public void Dispose()
    {
        _aes.Dispose();
        CryptographicOperations.ZeroMemory(_fileKey);
    }
}
