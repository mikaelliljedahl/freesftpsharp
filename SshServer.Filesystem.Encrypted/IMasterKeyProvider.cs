namespace SshServer.Filesystem.Encrypted;

/// <summary>
/// The master keys of the encrypted storage. The active key encrypts new files; every key that a file header names
/// decrypts. Rotation: add a key, make it the active key, keep the old key for the old files. A later backend (a key
/// vault or a cloud KMS) implements this interface; the file format does not change.
/// </summary>
public interface IMasterKeyProvider
{
    /// <summary>The key that encrypts new files.</summary>
    ValueTask<MasterKey> GetActiveKeyAsync(CancellationToken ct);

    /// <summary>The key with this 16 byte header id (<see cref="MasterKey.KeyId"/>), or null when it is not known.</summary>
    ValueTask<MasterKey?> FindKeyAsync(ReadOnlyMemory<byte> keyId, CancellationToken ct);
}
