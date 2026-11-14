using System.Security.Cryptography;

namespace SshServer.Filesystem.Encrypted;

/// <summary>
/// A 256-bit master key of the encrypted storage with its id. The key bytes are not public: only the encrypted storage
/// uses them, and <see cref="ToString"/> shows only the id, so a key never reaches a log.
/// </summary>
public sealed class MasterKey
{
    private readonly byte[] _key;

    /// <param name="id">The configured id, for example "2026-01". The file header stores <see cref="KeyId"/>, a hash of it.</param>
    /// <param name="key">The 32 key bytes; the instance keeps a copy.</param>
    public MasterKey(string id, ReadOnlySpan<byte> key)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("The key id is not set.", nameof(id));
        if (key.Length != EncryptedFileFormat.MasterKeySize)
            throw new ArgumentException($"The key '{id}' must be {EncryptedFileFormat.MasterKeySize} bytes, not {key.Length}.", nameof(key));
        Id = id;
        _key = key.ToArray();
        KeyId = EncryptedFileFormat.KeyIdOf(id);
    }

    /// <summary>The configured id.</summary>
    public string Id { get; }

    /// <summary>The 16 byte id in the file header: the first 16 bytes of SHA-256 of the UTF-8 <see cref="Id"/>.</summary>
    public ReadOnlyMemory<byte> KeyId { get; }

    internal ReadOnlySpan<byte> Key => _key;

    public override string ToString() => $"MasterKey {Id}";

    /// <summary>True when <paramref name="keyId"/> is the header id of this key.</summary>
    public bool HasKeyId(ReadOnlySpan<byte> keyId) => CryptographicOperations.FixedTimeEquals(KeyId.Span, keyId);
}
