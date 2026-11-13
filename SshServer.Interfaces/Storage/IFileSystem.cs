namespace SshServer.Interfaces.Storage;

/// <summary>
/// One user's storage: the plug-in point for every storage backend and every storage rule (decorator).
/// <para>
/// Paths are virtual: "/" separated, "/" is the user root. A backend accepts any path from a client and normalizes it
/// with <see cref="VirtualPath.Normalize"/>, so a path never leaves the user root. The user root cannot be removed,
/// moved, replaced or have its permissions changed (<see cref="FileSystemError.PermissionDenied"/>).
/// </para>
/// <para>
/// A failed operation throws only <see cref="FileSystemException"/>; its message has only virtual paths. An operation
/// that needs a capability the backend does not have (<see cref="Capabilities"/>) throws
/// <see cref="FileSystemError.OpNotSupported"/>. Every backend passes <c>FileSystemConformanceTests&lt;TFixture&gt;</c>.
/// </para>
/// </summary>
public interface IFileSystem
{
    /// <summary>What this storage can do.</summary>
    StorageCapabilities Capabilities { get; }

    /// <summary>
    /// The entry at <paramref name="path"/>, or null when it does not exist (also when a parent is a file).
    /// <paramref name="followLinks"/> false (SFTP LSTAT) reports a link itself; a backend without
    /// <see cref="StorageCapabilities.Symlinks"/> ignores it.
    /// </summary>
    ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct);

    /// <summary>
    /// The entries of a directory, without "." and "..", in no defined order. Throws <see cref="FileSystemError.NoSuchFile"/>
    /// for a missing path and <see cref="FileSystemError.NotADirectory"/> for a file, at the first
    /// <c>MoveNextAsync</c>. Entries that the user cannot reach (for example a link to outside the root) are left out.
    /// </summary>
    IAsyncEnumerable<FileSystemEntry> ListAsync(string path, CancellationToken ct);

    /// <summary>
    /// Opens a file. Throws <see cref="FileSystemError.NoSuchFile"/> when the file (without <see cref="FileOpenFlags.Create"/>)
    /// or its parent directory does not exist, <see cref="FileSystemError.AlreadyExists"/> for
    /// <see cref="FileOpenFlags.Exclusive"/> and an existing file, and <see cref="FileSystemError.IsADirectory"/> for a
    /// directory. <paramref name="initial"/> is applied only when the open creates the file. Other handles can read,
    /// write, rename and delete the file while it is open.
    /// </summary>
    ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct);

    /// <summary>
    /// Creates a directory. Throws <see cref="FileSystemError.AlreadyExists"/> when the path exists (file or directory)
    /// and <see cref="FileSystemError.NoSuchFile"/> when the parent does not exist.
    /// </summary>
    ValueTask CreateDirectoryAsync(string path, CancellationToken ct);

    /// <summary>
    /// Removes a file. Throws <see cref="FileSystemError.NoSuchFile"/> for a missing path and
    /// <see cref="FileSystemError.IsADirectory"/> for a directory.
    /// </summary>
    ValueTask DeleteFileAsync(string path, CancellationToken ct);

    /// <summary>
    /// Removes an empty directory. Throws <see cref="FileSystemError.NoSuchFile"/> for a missing path,
    /// <see cref="FileSystemError.NotADirectory"/> for a file, <see cref="FileSystemError.DirectoryNotEmpty"/> and,
    /// for the user root, <see cref="FileSystemError.PermissionDenied"/>.
    /// </summary>
    ValueTask DeleteDirectoryAsync(string path, CancellationToken ct);

    /// <summary>
    /// Renames a file or directory (needs <see cref="StorageCapabilities.Rename"/>). Throws
    /// <see cref="FileSystemError.NoSuchFile"/> when <paramref name="oldPath"/> or the parent of <paramref name="newPath"/>
    /// does not exist, <see cref="FileSystemError.PermissionDenied"/> for the user root (as source or target), and
    /// <see cref="FileSystemError.AlreadyExists"/> when <paramref name="newPath"/> exists. With
    /// <see cref="RenameFlags.ReplaceExisting"/> an existing file at the target is replaced, atomically where the
    /// storage allows it; a directory source with an existing target still throws <see cref="FileSystemError.AlreadyExists"/>,
    /// and a file onto a directory throws <see cref="FileSystemError.IsADirectory"/>.
    /// </summary>
    ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct);

    /// <summary>
    /// Changes the size, permissions and times of a file or directory, in this order. Throws
    /// <see cref="FileSystemError.NoSuchFile"/> for a missing path, <see cref="FileSystemError.PermissionDenied"/> for the
    /// permissions of the user root, and <see cref="FileSystemError.OpNotSupported"/> for a change that needs a missing
    /// capability.
    /// </summary>
    ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct);

    /// <summary>
    /// The size and free space of the storage that holds <paramref name="path"/> (SFTP statvfs@openssh.com), or null
    /// when the storage cannot tell. Throws <see cref="FileSystemError.NoSuchFile"/> when the path does not exist.
    /// </summary>
    ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct);

    // ---- Members of the synchronous interface, removed when the SFTP adapter is ported. A backend that has only the new members does not implement them. ----

    bool RemoveDirectory(string pathToRemove) => throw new NotSupportedException();
    bool MakeDirectory(string newPath) => throw new NotSupportedException();
    bool DirectoryExists(string path) => throw new NotSupportedException();
    bool FileExists(string path) => throw new NotSupportedException();
    Stream OpenStreamRead(string path) => throw new NotSupportedException();
    Stream OpenStreamWrite(string path) => throw new NotSupportedException();
    Stream OpenStreamWrite(string path, FileMode mode) => throw new NotSupportedException();
    IEnumerable<Resource> GetFiles(string path) => throw new NotSupportedException();
    IEnumerable<Resource> GetDirectories(string path) => throw new NotSupportedException();
    bool RemoveFile(string path) => throw new NotSupportedException();
    ulong GetSize(string path) => throw new NotSupportedException();
    DateTime GetDirectoryLastModified(string path) => throw new NotSupportedException();
    DateTime GetDirectoryLastAccessed(string path) => throw new NotSupportedException();
    DateTime GetFileLastModified(string path) => throw new NotSupportedException();
    DateTime GetFileLastAccessed(string path) => throw new NotSupportedException();
    bool MoveFileOrDirectory(string oldpath, string newpath) => throw new NotSupportedException();

    /// <summary>Returns the type, size, times and permissions of a file or directory, or null if the path does not exist.</summary>
    FileSystemEntryInfo? GetInfo(string path) => throw new NotSupportedException();

    /// <summary>
    /// Opens a file with the given mode and access. Other handles can read, write and delete the file
    /// while the stream is open (SFTP clients open the same file again, for example for SETSTAT).
    /// </summary>
    Stream OpenFile(string path, FileMode mode, FileAccess access) => throw new NotSupportedException();

    /// <summary>Truncates or extends a file to <paramref name="length"/> bytes.</summary>
    void SetFileLength(string path, long length) => throw new NotSupportedException();

    /// <summary>Sets the last access and/or last write time (UTC) of a file or directory. A null time is not changed.</summary>
    void SetTimes(string path, DateTime? lastAccessUtc, DateTime? lastWriteUtc) => throw new NotSupportedException();

    /// <summary>
    /// Sets the POSIX permission bits (rwxrwxrwx, the lowest 9 bits of <paramref name="mode"/>) of a file
    /// or directory. Other bits (file type, setuid, setgid, sticky) are ignored. A platform without POSIX
    /// permissions applies what it can.
    /// </summary>
    void SetPermissions(string path, uint mode) => throw new NotSupportedException();

    /// <summary>
    /// Renames a file or directory with POSIX rename semantics: an existing file at <paramref name="newPath"/>
    /// is replaced, atomically where the storage allows it (SFTP posix-rename@openssh.com). A directory is
    /// never replaced. Throws <see cref="FileNotFoundException"/> when <paramref name="oldPath"/> does not
    /// exist, <see cref="IOException"/> when the target cannot be replaced, and
    /// <see cref="UnauthorizedAccessException"/> for the user root.
    /// </summary>
    void RenameReplacing(string oldPath, string newPath) => throw new NotSupportedException();

    /// <summary>
    /// The size and free space of the storage that holds <paramref name="path"/> (SFTP statvfs@openssh.com),
    /// or null when the storage cannot tell. Throws <see cref="FileNotFoundException"/> when the path does
    /// not exist.
    /// </summary>
    StorageSpace? GetStorageSpace(string path) => throw new NotSupportedException();
}

/// <param name="Type">File or directory.</param>
/// <param name="Length">The size in bytes; 0 for a directory.</param>
/// <param name="LastAccessUtc">The last access time (UTC).</param>
/// <param name="LastWriteUtc">The last write time (UTC).</param>
/// <param name="Permissions">The POSIX permission bits (rwxrwxrwx, lowest 9 bits).</param>
public sealed record FileSystemEntryInfo(ResourceType Type, ulong Length, DateTime LastAccessUtc, DateTime LastWriteUtc, uint Permissions);

public record struct Resource(string Name, string FullName, ResourceType Type, ulong Length);

public enum ResourceType
{
    File = 1,
    Folder = 2
}
