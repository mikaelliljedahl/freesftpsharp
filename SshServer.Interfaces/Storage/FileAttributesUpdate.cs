namespace SshServer.Interfaces.Storage;

/// <summary>
/// The attributes to change with <see cref="IFileSystem.SetAttributesAsync"/> or <see cref="IFileHandle.SetAttributesAsync"/>,
/// or to give a new file in <see cref="IFileSystem.OpenAsync"/>. A null value is not changed. The backend applies the
/// size first, then the permissions, then the times.
/// </summary>
public sealed record FileAttributesUpdate
{
    /// <summary>Truncate or extend the file to this size (needs <see cref="StorageCapabilities.RandomAccessWrite"/>).</summary>
    public long? Size { get; init; }

    /// <summary>
    /// The POSIX permission bits; only the lowest 9 bits (rwxrwxrwx) are used, the file type, setuid, setgid and
    /// sticky bits are ignored (needs <see cref="StorageCapabilities.SetPermissions"/>). A platform without POSIX
    /// permissions applies what it can.
    /// </summary>
    public uint? Permissions { get; init; }

    /// <summary>The last access time, UTC (needs <see cref="StorageCapabilities.SetTimes"/>).</summary>
    public DateTime? LastAccessTimeUtc { get; init; }

    /// <summary>The last write time, UTC (needs <see cref="StorageCapabilities.SetTimes"/>).</summary>
    public DateTime? LastWriteTimeUtc { get; init; }

    /// <summary>True when the update changes the access or write time.</summary>
    public bool HasTimes => LastAccessTimeUtc != null || LastWriteTimeUtc != null;

    /// <summary>True when the update changes nothing.</summary>
    public bool IsEmpty => Size == null && Permissions == null && !HasTimes;
}
