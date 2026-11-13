namespace SshServer.Interfaces.Storage;

/// <summary>How <see cref="IFileSystem.OpenAsync"/> opens a file. The values are the SSH_FXF_* flags of SFTP version 3.</summary>
[Flags]
public enum FileOpenFlags
{
    None = 0,

    /// <summary>The handle can read.</summary>
    Read = 1 << 0,

    /// <summary>The handle can write.</summary>
    Write = 1 << 1,

    /// <summary>Every write goes to the end of the file, whatever its offset (needs <see cref="StorageCapabilities.Append"/>).</summary>
    Append = 1 << 2,

    /// <summary>Create the file if it does not exist. The parent directory must exist.</summary>
    Create = 1 << 3,

    /// <summary>With <see cref="Create"/>: an existing file is truncated to 0 bytes.</summary>
    Truncate = 1 << 4,

    /// <summary>With <see cref="Create"/>: fail with <see cref="FileSystemError.AlreadyExists"/> if the file exists.</summary>
    Exclusive = 1 << 5,
}

/// <summary>How <see cref="IFileSystem.RenameAsync"/> treats an existing target.</summary>
[Flags]
public enum RenameFlags
{
    /// <summary>An existing target fails with <see cref="FileSystemError.AlreadyExists"/> (SFTP RENAME).</summary>
    None = 0,

    /// <summary>
    /// POSIX rename(2): an existing file at the target is replaced, atomically where the storage allows it (SFTP
    /// posix-rename@openssh.com). A directory is never replaced.
    /// </summary>
    ReplaceExisting = 1 << 0,
}
