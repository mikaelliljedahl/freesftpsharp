namespace SshServer.Interfaces.Storage;

/// <summary>The type of a <see cref="FileSystemEntry"/>.</summary>
public enum FileSystemEntryType
{
    File = 1,
    Directory = 2,

    /// <summary>A symbolic link that is not followed (only a backend with <see cref="StorageCapabilities.Symlinks"/>).</summary>
    Symlink = 3,
}

/// <summary>A file, directory or link, from <see cref="IFileSystem.StatAsync"/>, <see cref="IFileSystem.ListAsync"/> or <see cref="IFileHandle.StatAsync"/>.</summary>
/// <param name="Name">The last segment of the virtual path; "/" for the user root.</param>
/// <param name="Type">File, directory or link.</param>
/// <param name="Size">The size in bytes; 0 for a directory.</param>
/// <param name="LastWriteTimeUtc">The last write (modification) time, UTC.</param>
/// <param name="LastAccessTimeUtc">The last access time, UTC. A backend that does not know it gives the last write time.</param>
public sealed record FileSystemEntry(string Name, FileSystemEntryType Type, long Size, DateTime LastWriteTimeUtc, DateTime LastAccessTimeUtc)
{
    /// <summary>The POSIX permission bits (rwxrwxrwx, the lowest 9 bits), or null when the storage has none.</summary>
    public uint? Permissions { get; init; }

    /// <summary>The POSIX user id of the owner, or null when the storage has none.</summary>
    public uint? UserId { get; init; }

    /// <summary>The POSIX group id, or null when the storage has none.</summary>
    public uint? GroupId { get; init; }

    public bool IsDirectory => Type == FileSystemEntryType.Directory;
}
