namespace FxSsh.Services.Sftp
{
    /// <summary>
    /// Optional capability of an <see cref="ISftpFileSystem"/>: posix-rename@openssh.com
    /// (OpenSSH PROTOCOL 4.3). The engine announces the extension only when the file system
    /// implements this interface.
    /// </summary>
    public interface ISftpPosixRenameFileSystem
    {
        /// <summary>
        /// Rename with POSIX rename(2) semantics: an existing file at <paramref name="newPath"/>
        /// is replaced, atomically where the storage allows it.
        /// </summary>
        void PosixRename(string oldPath, string newPath);
    }

    /// <summary>
    /// Optional capability of an <see cref="ISftpFileSystem"/>: statvfs@openssh.com
    /// (OpenSSH PROTOCOL 4.4). The engine announces the extension only when the file system
    /// implements this interface.
    /// </summary>
    public interface ISftpStatVfsFileSystem
    {
        /// <summary>The statistics of the file system that contains <paramref name="path"/>.</summary>
        SftpFileSystemStats GetFileSystemStats(string path);
    }

    /// <summary>
    /// Optional capability of an <see cref="ISftpFileSystem"/>: fsync@openssh.com
    /// (OpenSSH PROTOCOL 4.6). The engine announces the extension only when the file system
    /// implements this interface.
    /// </summary>
    public interface ISftpFsyncFileSystem
    {
        /// <summary>Write the data of an open file (returned by this file system) to stable storage.</summary>
        void Sync(ISftpFileHandle handle);
    }

    /// <summary>The fields of a statvfs@openssh.com reply (struct statvfs).</summary>
    public sealed class SftpFileSystemStats
    {
        /// <summary>f_bsize: file system block size.</summary>
        public ulong BlockSize { get; set; }
        /// <summary>f_frsize: fundamental block size; the block counts are in this unit.</summary>
        public ulong FragmentSize { get; set; }
        /// <summary>f_blocks: number of blocks.</summary>
        public ulong Blocks { get; set; }
        /// <summary>f_bfree: free blocks.</summary>
        public ulong FreeBlocks { get; set; }
        /// <summary>f_bavail: free blocks for a non-root user.</summary>
        public ulong AvailableBlocks { get; set; }
        /// <summary>f_files: number of inodes.</summary>
        public ulong Files { get; set; }
        /// <summary>f_ffree: free inodes.</summary>
        public ulong FreeFiles { get; set; }
        /// <summary>f_favail: free inodes for a non-root user.</summary>
        public ulong AvailableFiles { get; set; }
        /// <summary>f_fsid: file system id.</summary>
        public ulong FileSystemId { get; set; }
        /// <summary>f_flag: SSH_FXE_STATVFS_ST_RDONLY (1), SSH_FXE_STATVFS_ST_NOSUID (2).</summary>
        public ulong Flags { get; set; }
        /// <summary>f_namemax: maximum file name length.</summary>
        public ulong MaxNameLength { get; set; }
    }
}
