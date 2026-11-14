namespace SshServer.Interfaces.Storage;

/// <summary>
/// The reason of a <see cref="FileSystemException"/>. Every protocol maps these codes to its own status codes
/// (SFTP: SSH_FX_*), so a backend chooses the code from the cause, never from the protocol.
/// </summary>
public enum FileSystemError
{
    /// <summary>Another failure, for example an I/O error of the storage. SFTP: SSH_FX_FAILURE.</summary>
    Failure = 0,

    /// <summary>The path (or, for a new entry, its parent directory) does not exist. SFTP: SSH_FX_NO_SUCH_FILE.</summary>
    NoSuchFile,

    /// <summary>
    /// The operation is not allowed: the path leads outside the user root (for example through a link), the user
    /// root cannot be removed, moved or changed, a handle was opened without the access that the call needs, or
    /// the storage refused access. SFTP: SSH_FX_PERMISSION_DENIED.
    /// </summary>
    PermissionDenied,

    /// <summary>A directory operation on a path that is a file. SFTP: SSH_FX_FAILURE (version 3 has no own code).</summary>
    NotADirectory,

    /// <summary>A file operation on a path that is a directory. SFTP: SSH_FX_FAILURE, except OPEN and REMOVE (PERMISSION_DENIED).</summary>
    IsADirectory,

    /// <summary>A directory that is not empty cannot be removed. SFTP: SSH_FX_FAILURE.</summary>
    DirectoryNotEmpty,

    /// <summary>The target path already exists. SFTP: SSH_FX_FAILURE.</summary>
    AlreadyExists,

    /// <summary>
    /// The storage cannot do this operation (see <see cref="IFileSystem.Capabilities"/>), for example a write at a
    /// random offset on an object store. SFTP: SSH_FX_OP_UNSUPPORTED.
    /// </summary>
    OpNotSupported,

    /// <summary>A storage limit was reached. SFTP: SSH_FX_FAILURE (version 3 has no own code).</summary>
    QuotaExceeded,

    /// <summary>The path is not valid for the storage, for example it contains a NUL character. SFTP: SSH_FX_BAD_MESSAGE.</summary>
    InvalidPath,
}
