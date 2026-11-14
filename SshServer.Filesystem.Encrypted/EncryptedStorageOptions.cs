namespace SshServer.Filesystem.Encrypted;

/// <summary>
/// The configuration section <c>Storage:Encryption</c>. Nothing is required while <see cref="Enabled"/> is false.
/// </summary>
public sealed class EncryptedStorageOptions
{
    public const string SectionName = "Storage:Encryption";

    /// <summary>
    /// Store the user roots of the users without a storage configuration encrypted ("local-encrypted") instead of plain
    /// ("local"). Use it only with new, empty user root directories: files that are not encrypted cannot be read.
    /// The keys are needed also when it is false, for a user or virtual folder that selects "local-encrypted".
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>The <see cref="EncryptionKeyOptions.Id"/> of the key that encrypts new files.</summary>
    public string? ActiveKeyId { get; set; }

    /// <summary>Every key: the active key and the old keys that still decrypt old files.</summary>
    public List<EncryptionKeyOptions> Keys { get; set; } = [];

    public override string ToString() => $"Encryption Enabled={Enabled} ActiveKeyId={ActiveKeyId} Keys={string.Join(",", Keys.Select(k => k.Id))}";
}

/// <summary>One master key: an id and exactly one of <see cref="Key"/> or <see cref="KeyFile"/>. A secret: never logged.</summary>
public sealed class EncryptionKeyOptions
{
    /// <summary>A name of the key, for example "2026-01". The file header stores a hash of it, so do not rename a key.</summary>
    public string? Id { get; set; }

    /// <summary>The key, base64 of 32 random bytes (for example from an environment variable or user secrets).</summary>
    public string? Key { get; set; }

    /// <summary>
    /// A file that has the key as base64. On Linux and macOS only the owner may read it (mode 0600 or 0400).
    /// A relative path is relative to the working directory.
    /// </summary>
    public string? KeyFile { get; set; }

    public override string ToString() => $"Key {Id}";
}
