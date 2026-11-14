namespace SshServer.Interfaces.Storage;

/// <summary>
/// What a storage backend can do (<see cref="IFileSystem.Capabilities"/>). Decorators, protocols and the UI read
/// these flags; they never test the type of the backend. An operation that needs a missing capability throws
/// <see cref="FileSystemException"/> with <see cref="FileSystemError.OpNotSupported"/>.
/// </summary>
[Flags]
public enum StorageCapabilities
{
    /// <summary>
    /// Only the basic operations: stat, list, open, sequential writes (each write starts at the current end of the
    /// file, as in an upload to an object store), create and delete.
    /// </summary>
    None = 0,

    /// <summary>Writes at any offset, also before the end or past it, and changes of the file size (<see cref="FileAttributesUpdate.Size"/>).</summary>
    RandomAccessWrite = 1 << 0,

    /// <summary>Open an existing file with <see cref="FileOpenFlags.Append"/>.</summary>
    Append = 1 << 1,

    /// <summary><see cref="IFileSystem.RenameAsync"/> of files and directories, with and without <see cref="RenameFlags.ReplaceExisting"/>.</summary>
    Rename = 1 << 2,

    /// <summary>Set the access and write times (<see cref="FileAttributesUpdate.LastAccessTimeUtc"/>, <see cref="FileAttributesUpdate.LastWriteTimeUtc"/>).</summary>
    SetTimes = 1 << 3,

    /// <summary>Set the POSIX permission bits (<see cref="FileAttributesUpdate.Permissions"/>).</summary>
    SetPermissions = 1 << 4,

    /// <summary>The storage reports symbolic links as <see cref="FileSystemEntryType.Symlink"/> when they are not followed.</summary>
    Symlinks = 1 << 5,

    /// <summary>The storage can copy a file without sending the data through the server.</summary>
    ServerSideCopy = 1 << 6,

    /// <summary>
    /// The storage treats paths that differ only in case as the same path, and ignores trailing dots and spaces of a
    /// name (the Windows rules; also macOS by default). The permission decorator compares its paths the same way.
    /// </summary>
    CaseInsensitivePaths = 1 << 7,
}
