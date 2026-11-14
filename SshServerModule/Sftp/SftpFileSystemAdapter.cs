#nullable enable
using FxSsh.Services.Sftp;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Storage;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace SshServerModule.Sftp
{
    /// <summary>
    /// Gives the upstream FxSsh SFTP engine (<see cref="SftpService"/>) access to one user's <see cref="IFileSystem"/>.
    /// <para>
    /// The engine sends the paths of the client unchanged. The <see cref="IFileSystem"/> resolves them as virtual paths,
    /// where "/" is the user root, and it is the security boundary: a path can never leave the user root, and the user
    /// root cannot be removed, moved or changed.
    /// </para>
    /// <para>
    /// The engine is synchronous and the storage is asynchronous: every call waits through <see cref="SyncBridge"/>
    /// (see there why this cannot deadlock). The engine gives no cancellation, so the calls use
    /// <see cref="CancellationToken.None"/>.
    /// </para>
    /// <para>
    /// Errors: the storage throws <see cref="FileSystemException"/>. This adapter maps each <see cref="FileSystemError"/>
    /// to the exception type that the engine maps to the SSH_FX status code: NoSuchFile gives NO_SUCH_FILE,
    /// PermissionDenied gives PERMISSION_DENIED, OpNotSupported gives OP_UNSUPPORTED, InvalidPath gives BAD_MESSAGE, and
    /// the others give FAILURE (SFTP version 3 has no own code for them); IsADirectory of OPEN and REMOVE gives
    /// PERMISSION_DENIED. The engine sends the exception message to the client, so the new exception has only the
    /// virtual path in its message. Any other exception is a bug: it is logged as an error and gives FAILURE.
    /// </para>
    /// </summary>
    public sealed class SftpFileSystemAdapter : ISftpFileSystem, ISftpPosixRenameFileSystem, ISftpStatVfsFileSystem, ISftpFsyncFileSystem
    {
        private const uint RegularFileType = 0x8000;
        private const uint DirectoryType = 0x4000;
        private const uint DefaultFilePermissions = 0x1A4;      // rw-r--r--, for a storage without permissions
        private const uint DefaultDirectoryPermissions = 0x1ED; // rwxr-xr-x
        private const string OwnExceptionKey = "FreeSftpSharp.SftpMessage";

        /// <summary>The block size of the statvfs reply; the byte counts of the storage are given in these blocks.</summary>
        private const ulong StatVfsBlockSize = 4096;
        private const ulong MaxNameLength = 255;

        private static readonly CancellationToken None = CancellationToken.None;

        private readonly IFileSystem _fileSystem;
        private readonly ILogger _logger;
        private readonly string _username;

        public SftpFileSystemAdapter(IFileSystem fileSystem, ILogger logger, string username)
        {
            _fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _username = username;
        }

        /// <summary>
        /// The canonical form of a path for SSH_FXP_REALPATH. The working directory of a session is always
        /// the user root "/", so a relative path starts there. Only "/" is a separator, because "\" is an
        /// ordinary character in an SFTP path (the file system treats "\" as a separator later, so such a
        /// path still cannot leave the user root). "." segments are removed, and a ".." segment removes the
        /// previous segment and stays at the root. "~" (sent by WinSCP and FileZilla) is the user root.
        /// </summary>
        public static string NormalizePath(string path)
        {
            path ??= string.Empty;
            if (path == "~" || path.StartsWith("~/", StringComparison.Ordinal))
                path = path.Substring(1);

            var segments = new List<string>();
            foreach (var segment in path.Split('/'))
            {
                if (segment.Length == 0 || segment == ".")
                    continue;

                if (segment == "..")
                {
                    if (segments.Count > 0)
                        segments.RemoveAt(segments.Count - 1);
                    continue;
                }

                segments.Add(segment);
            }

            return "/" + string.Join('/', segments);
        }

        public string RealPath(string path) => NormalizePath(path);

        public ISftpFileHandle OpenFile(string path, SftpOpenFlags flags, SftpFileAttributes attributes)
        {
            // The values of FileOpenFlags are the SSH_FXF_* flags. The engine has already rejected TRUNC or EXCL
            // without CREAT. The attributes of OPEN are not applied (as before issue #51).
            var openFlags = (FileOpenFlags)(uint)flags;
            if ((openFlags & FileOpenFlags.Write) != 0)
                _logger.LogInformation("User {Username} opens {Path} for writing ({Flags}).", _username, path, openFlags);
            else
                _logger.LogDebug("User {Username} opens {Path} for reading.", _username, path);

            try
            {
                var handle = SyncBridge.Wait(_fileSystem.OpenAsync(path, openFlags, null, None));
                return new FileHandle(this, handle, path);
            }
            catch (FileSystemException ex) when (ex.Error == FileSystemError.IsADirectory)
            {
                throw Own(new UnauthorizedAccessException($"Is a directory: {path}"));
            }
            catch (Exception ex)
            {
                throw Translate(ex, path);
            }
        }

        public ISftpDirectoryHandle OpenDirectory(string path)
        {
            try
            {
                var directory = Stat(path) ?? throw new FileSystemException(FileSystemError.NoSuchFile, $"No such directory: {path}");
                if (!directory.IsDirectory)
                    throw new FileSystemException(FileSystemError.NotADirectory, $"Not a directory: {path}");

                var parent = Stat(path + "/..") ?? directory; // the parent of the root is the root
                var first = new[]
                {
                    new SftpFileEntry { FileName = ".", Attributes = ToAttributes(directory) },
                    new SftpFileEntry { FileName = "..", Attributes = ToAttributes(parent) },
                };
                return new DirectoryHandle(this, first, _fileSystem.ListAsync(path, None).GetAsyncEnumerator(None), path);
            }
            catch (Exception ex)
            {
                throw Translate(ex, path);
            }
        }

        public SftpFileAttributes GetAttributes(string path, bool followLinks)
        {
            try
            {
                var entry = SyncBridge.Wait(_fileSystem.StatAsync(path, followLinks, None))
                    ?? throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");
                return ToAttributes(entry);
            }
            catch (Exception ex)
            {
                throw Translate(ex, path);
            }
        }

        public void SetAttributes(string path, SftpFileAttributes attributes)
        {
            _logger.LogDebug("User {Username} sets the attributes of {Path}.", _username, path);
            try
            {
                SyncBridge.Wait(_fileSystem.SetAttributesAsync(path, ToUpdate(attributes), None));
            }
            catch (Exception ex)
            {
                throw Translate(ex, path);
            }
        }

        public void RemoveFile(string path)
        {
            _logger.LogInformation("User {Username} removes the file {Path}.", _username, path);
            try
            {
                SyncBridge.Wait(_fileSystem.DeleteFileAsync(path, None));
            }
            catch (FileSystemException ex) when (ex.Error == FileSystemError.IsADirectory)
            {
                throw Own(new UnauthorizedAccessException($"Is a directory, use RMDIR: {path}"));
            }
            catch (Exception ex)
            {
                throw Translate(ex, path);
            }
        }

        /// <summary>SSH_FXP_RENAME: SFTP version 3 does not overwrite an existing target.</summary>
        public void Rename(string oldPath, string newPath)
        {
            _logger.LogInformation("User {Username} renames {OldPath} to {NewPath}.", _username, oldPath, newPath);
            try
            {
                SyncBridge.Wait(_fileSystem.RenameAsync(oldPath, newPath, RenameFlags.None, None));
            }
            catch (Exception ex)
            {
                throw Translate(ex, oldPath);
            }
        }

        /// <summary>posix-rename@openssh.com: like <see cref="Rename"/>, but an existing file at the target is replaced.</summary>
        public void PosixRename(string oldPath, string newPath)
        {
            _logger.LogInformation("User {Username} renames {OldPath} to {NewPath} (replacing).", _username, oldPath, newPath);
            try
            {
                SyncBridge.Wait(_fileSystem.RenameAsync(oldPath, newPath, RenameFlags.ReplaceExisting, None));
            }
            catch (Exception ex)
            {
                throw Translate(ex, oldPath);
            }
        }

        /// <summary>
        /// statvfs@openssh.com: the size and free space of the storage of the user root, in 4 KiB blocks. The
        /// reply has no paths. The inode counts are 0 (unknown).
        /// </summary>
        public SftpFileSystemStats GetFileSystemStats(string path)
        {
            try
            {
                var space = SyncBridge.Wait(_fileSystem.GetStorageSpaceAsync(path, None))
                    ?? throw new FileSystemException(FileSystemError.Failure, $"The storage space is not known: {path}");
                return new SftpFileSystemStats
                {
                    BlockSize = StatVfsBlockSize,
                    FragmentSize = StatVfsBlockSize,
                    Blocks = space.TotalBytes / StatVfsBlockSize,
                    FreeBlocks = space.FreeBytes / StatVfsBlockSize,
                    AvailableBlocks = space.AvailableBytes / StatVfsBlockSize,
                    MaxNameLength = MaxNameLength,
                };
            }
            catch (Exception ex)
            {
                throw Translate(ex, path);
            }
        }

        /// <summary>fsync@openssh.com: writes the data of an open file to the storage (<see cref="IFileHandle.FlushAsync"/>).</summary>
        public void Sync(ISftpFileHandle handle)
        {
            if (handle is not FileHandle file)
                throw Own(new IOException("Not a file handle of this session."));
            file.Sync();
        }

        public void MakeDirectory(string path, SftpFileAttributes attributes)
        {
            _logger.LogInformation("User {Username} creates the directory {Path}.", _username, path);
            try
            {
                SyncBridge.Wait(_fileSystem.CreateDirectoryAsync(path, None));
                if (attributes?.Permissions is { } permissions)
                    SyncBridge.Wait(_fileSystem.SetAttributesAsync(path, new FileAttributesUpdate { Permissions = permissions }, None));
            }
            catch (Exception ex)
            {
                throw Translate(ex, path);
            }
        }

        public void RemoveDirectory(string path)
        {
            _logger.LogInformation("User {Username} removes the directory {Path}.", _username, path);
            try
            {
                SyncBridge.Wait(_fileSystem.DeleteDirectoryAsync(path, None));
            }
            catch (Exception ex)
            {
                throw Translate(ex, path);
            }
        }

        private FileSystemEntry? Stat(string path) => SyncBridge.Wait(_fileSystem.StatAsync(path, followLinks: true, None));

        private static SftpFileAttributes ToAttributes(FileSystemEntry entry)
        {
            var isDirectory = entry.IsDirectory;
            var permissions = entry.Permissions ?? (isDirectory ? DefaultDirectoryPermissions : DefaultFilePermissions);
            return new SftpFileAttributes
            {
                Size = isDirectory ? null : (ulong)Math.Max(0, entry.Size),
                UserId = entry.UserId,
                GroupId = entry.GroupId,
                Permissions = (isDirectory ? DirectoryType : RegularFileType) | (permissions & 0x1FF),
                AccessTime = ToUnixTime(entry.LastAccessTimeUtc),
                ModificationTime = ToUnixTime(entry.LastWriteTimeUtc),
            };
        }

        /// <summary>
        /// The size, permissions and times of SSH_FXP_SETSTAT and SSH_FXP_FSETSTAT. The uid and gid are ignored: the
        /// server has no user or group ids to give.
        /// </summary>
        private static FileAttributesUpdate ToUpdate(SftpFileAttributes? attributes)
        {
            if (attributes == null)
                return new FileAttributesUpdate();
            if (attributes.Size > long.MaxValue)
                throw new FileSystemException(FileSystemError.Failure, "The size is too large.");
            return new FileAttributesUpdate
            {
                Size = (long?)attributes.Size,
                Permissions = attributes.Permissions,
                LastAccessTimeUtc = FromUnixTime(attributes.AccessTime),
                LastWriteTimeUtc = FromUnixTime(attributes.ModificationTime),
            };
        }

        private static uint ToUnixTime(DateTime utc)
        {
            var seconds = new DateTimeOffset(DateTime.SpecifyKind(utc, DateTimeKind.Utc)).ToUnixTimeSeconds();
            return (uint)Math.Clamp(seconds, 0, uint.MaxValue);
        }

        private static DateTime? FromUnixTime(uint? seconds)
            => seconds is { } value ? DateTimeOffset.FromUnixTimeSeconds(value).UtcDateTime : null;

        /// <summary>Marks an exception that this class made, so that <see cref="Translate"/> keeps it.</summary>
        private static Exception Own(Exception ex)
        {
            ex.Data[OwnExceptionKey] = true;
            return ex;
        }

        /// <summary>
        /// Replaces an exception of the file system with the exception type that the engine maps to the SSH_FX code of
        /// its <see cref="FileSystemError"/>, with only the virtual path in its message. The original exception is logged
        /// here: as a warning for <see cref="FileSystemError.Failure"/> (a failure of the storage), at debug level for the other
        /// codes of a <see cref="FileSystemException"/> (a client can cause them), at error level otherwise.
        /// An unexpected exception becomes an <see cref="InvalidOperationException"/>, which the engine answers with
        /// SSH_FX_FAILURE and logs as an error.
        /// </summary>
        private Exception Translate(Exception ex, string path)
        {
            if (ex.Data.Contains(OwnExceptionKey))
                return ex;

            if (ex is not FileSystemException fileSystemException)
            {
                _logger.LogError(ex, "SFTP operation of user {Username} on {Path} failed unexpectedly.", _username, path);
                return Own(new InvalidOperationException($"Internal error: {path}"));
            }

            // A storage failure (an I/O error of the disk, an error of a cloud storage) is not caused by the client,
            // and the client only gets SSH_FX_FAILURE: log the cause where an operator sees it.
            if (fileSystemException.Error == FileSystemError.Failure)
                _logger.LogWarning(ex, "SFTP operation of user {Username} on {Path} failed in the storage.", _username, path);
            else
                _logger.LogDebug(ex, "SFTP operation of user {Username} on {Path} failed.", _username, path);
            return Own(fileSystemException.Error switch
            {
                FileSystemError.NoSuchFile => new FileNotFoundException($"No such file: {path}"),
                FileSystemError.PermissionDenied => new UnauthorizedAccessException($"Permission denied: {path}"),
                FileSystemError.OpNotSupported => new NotSupportedException($"Operation not supported by the storage: {path}"),
                FileSystemError.InvalidPath => new ArgumentException($"Bad request: {path}"),
                FileSystemError.NotADirectory => new IOException($"Not a directory: {path}"),
                FileSystemError.IsADirectory => new IOException($"Is a directory: {path}"),
                FileSystemError.DirectoryNotEmpty => new IOException($"The directory is not empty: {path}"),
                FileSystemError.AlreadyExists => new IOException($"Already exists: {path}"),
                FileSystemError.QuotaExceeded => new IOException($"Quota exceeded: {path}"),
                _ => new IOException($"Failure: {path}"),
            });
        }

        private sealed class FileHandle : ISftpFileHandle
        {
            private readonly SftpFileSystemAdapter _owner;
            private readonly IFileHandle _handle;
            private readonly string _path;
            private bool _disposed;

            public FileHandle(SftpFileSystemAdapter owner, IFileHandle handle, string path)
            {
                _owner = owner;
                _handle = handle;
                _path = path;
            }

            public int Read(long offset, Span<byte> buffer)
            {
                // The engine gives a span; the storage needs memory that survives an await.
                var rented = ArrayPool<byte>.Shared.Rent(buffer.Length);
                try
                {
                    var read = SyncBridge.Wait(_handle.ReadAsync(offset, rented.AsMemory(0, buffer.Length), None));
                    rented.AsSpan(0, read).CopyTo(buffer);
                    return read;
                }
                catch (Exception ex)
                {
                    throw _owner.Translate(ex, _path);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }

            public void Write(long offset, ReadOnlySpan<byte> data)
            {
                var rented = ArrayPool<byte>.Shared.Rent(data.Length);
                try
                {
                    data.CopyTo(rented);
                    SyncBridge.Wait(_handle.WriteAsync(offset, rented.AsMemory(0, data.Length), None));
                }
                catch (Exception ex)
                {
                    throw _owner.Translate(ex, _path);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }

            public SftpFileAttributes GetAttributes()
            {
                try
                {
                    return ToAttributes(SyncBridge.Wait(_handle.StatAsync(None)));
                }
                catch (Exception ex)
                {
                    throw _owner.Translate(ex, _path);
                }
            }

            public void SetAttributes(SftpFileAttributes attributes)
            {
                try
                {
                    SyncBridge.Wait(_handle.SetAttributesAsync(ToUpdate(attributes), None));
                }
                catch (Exception ex)
                {
                    throw _owner.Translate(ex, _path);
                }
            }

            public void Sync()
            {
                try
                {
                    SyncBridge.Wait(_handle.FlushAsync(None));
                }
                catch (Exception ex)
                {
                    throw _owner.Translate(ex, _path);
                }
            }

            /// <summary>
            /// Flushes and closes the file. A failed flush (for example a full disk) is reported to the client in the
            /// CLOSE status; the storage closes the file in all cases.
            /// </summary>
            public void Dispose()
            {
                if (_disposed)
                    return;
                _disposed = true;

                try
                {
                    SyncBridge.Wait(_handle.DisposeAsync());
                }
                catch (Exception ex)
                {
                    throw _owner.Translate(ex, _path);
                }
            }

            /// <summary>The session ended without a CLOSE: the storage drops an unfinished upload if it can.</summary>
            public void Abort()
            {
                if (_disposed)
                    return;
                _disposed = true;

                try
                {
                    SyncBridge.Wait(_handle.AbortAsync());
                }
                catch (Exception ex)
                {
                    throw _owner.Translate(ex, _path);
                }
            }
        }

        /// <summary>
        /// "." and "..", then the entries of the storage, read as the client asks for them: a large directory is never
        /// held in memory as a whole.
        /// </summary>
        private sealed class DirectoryHandle : ISftpDirectoryHandle
        {
            private readonly SftpFileSystemAdapter _owner;
            private readonly SftpFileEntry[] _first;
            private readonly IAsyncEnumerator<FileSystemEntry> _entries;
            private readonly string _path;
            private int _nextFirst;
            private bool _done;

            public DirectoryHandle(SftpFileSystemAdapter owner, SftpFileEntry[] first, IAsyncEnumerator<FileSystemEntry> entries, string path)
            {
                _owner = owner;
                _first = first;
                _entries = entries;
                _path = path;
            }

            public SftpFileEntry[] ReadEntries(int maxCount)
            {
                var batch = new List<SftpFileEntry>();
                while (batch.Count < maxCount && _nextFirst < _first.Length)
                    batch.Add(_first[_nextFirst++]);

                try
                {
                    while (batch.Count < maxCount && !_done)
                    {
                        if (!SyncBridge.Wait(_entries.MoveNextAsync()))
                        {
                            _done = true;
                            break;
                        }
                        var entry = _entries.Current;
                        batch.Add(new SftpFileEntry { FileName = entry.Name, Attributes = ToAttributes(entry) });
                    }
                }
                catch (Exception ex)
                {
                    throw _owner.Translate(ex, _path);
                }

                return batch.ToArray();
            }

            public void Dispose()
            {
                try
                {
                    SyncBridge.Wait(_entries.DisposeAsync());
                }
                catch (Exception ex)
                {
                    throw _owner.Translate(ex, _path);
                }
            }
        }
    }
}
