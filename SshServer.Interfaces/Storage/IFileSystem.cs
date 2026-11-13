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
    /// or its parent directory does not exist or is a file, <see cref="FileSystemError.AlreadyExists"/> for
    /// <see cref="FileOpenFlags.Exclusive"/> and an existing file, and <see cref="FileSystemError.IsADirectory"/> for a
    /// directory. The permissions in <paramref name="initial"/> are applied only when the open creates the file; its other values are ignored. Other handles can read,
    /// write, rename and delete the file while it is open.
    /// </summary>
    ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct);

    /// <summary>
    /// Creates a directory. Throws <see cref="FileSystemError.AlreadyExists"/> when the path exists (file or directory)
    /// and <see cref="FileSystemError.NoSuchFile"/> when the parent does not exist or is a file.
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

}
