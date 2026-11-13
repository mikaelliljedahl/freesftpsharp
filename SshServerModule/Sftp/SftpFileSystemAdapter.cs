using FxSsh.Services.Sftp;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SshServerModule.Sftp
{
    /// <summary>
    /// Gives the upstream FxSsh SFTP engine (<see cref="SftpService"/>) access to one user's
    /// <see cref="IFileSystem"/>.
    /// <para>
    /// The engine sends the paths of the client unchanged. The <see cref="IFileSystem"/> resolves them as
    /// virtual paths, where "/" is the user root, and it is the security boundary: a path can never leave
    /// the user root (<c>LocalFileSystem.GetPhysicalPath</c>), and the user root cannot be removed, moved
    /// or changed.
    /// </para>
    /// <para>
    /// The engine maps exceptions to SSH_FX status codes: <see cref="FileNotFoundException"/> and
    /// <see cref="DirectoryNotFoundException"/> give NO_SUCH_FILE, <see cref="UnauthorizedAccessException"/>
    /// gives PERMISSION_DENIED, and other exceptions give FAILURE. The engine sends the exception message
    /// to the client, so this adapter replaces every exception from the file system with one that has only
    /// the virtual path in its message. The physical path of the user root is never sent to the client.
    /// </para>
    /// </summary>
    public sealed class SftpFileSystemAdapter : ISftpFileSystem, ISftpPosixRenameFileSystem, ISftpStatVfsFileSystem, ISftpFsyncFileSystem
    {
        private const uint RegularFileType = 0x8000;
        private const uint DirectoryType = 0x4000;
        private const string OwnExceptionKey = "FreeSftpSharp.SftpMessage";

        /// <summary>The block size of the statvfs reply; the byte counts of the storage are given in these blocks.</summary>
        private const ulong StatVfsBlockSize = 4096;
        private const ulong MaxNameLength = 255;

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
            var access = default(FileAccess);
            if ((flags & SftpOpenFlags.Read) != 0) access |= FileAccess.Read;
            if ((flags & SftpOpenFlags.Write) != 0) access |= FileAccess.Write;
            var mode = MapMode(flags);
            var append = (flags & SftpOpenFlags.Append) != 0;

            if ((access & FileAccess.Write) != 0)
                _logger.LogInformation("User {Username} opens {Path} for writing ({Mode}).", _username, path, mode);
            else
                _logger.LogDebug("User {Username} opens {Path} for reading.", _username, path);

            try
            {
                if (_fileSystem.DirectoryExists(path))
                    throw Own(new UnauthorizedAccessException($"Is a directory: {path}"));

                var stream = _fileSystem.OpenFile(path, mode, access);
                return new FileHandle(this, stream, path, append);
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
                if (!_fileSystem.DirectoryExists(path))
                {
                    if (_fileSystem.FileExists(path))
                        throw Own(new IOException($"Not a directory: {path}"));
                    throw Own(new DirectoryNotFoundException($"No such directory: {path}"));
                }

                var entries = new List<SftpFileEntry>
                {
                    Entry(".", path),
                    Entry("..", path + "/.."),
                };
                // GetDirectories also gives ".." below the root; "." and ".." are added above for every directory.
                foreach (var dir in _fileSystem.GetDirectories(path).Where(d => d.Name != ".." && d.Name != "."))
                    entries.Add(Entry(dir.Name, dir.FullName));
                foreach (var file in _fileSystem.GetFiles(path))
                    entries.Add(Entry(file.Name, file.FullName));

                return new DirectoryHandle(entries.Where(e => e.Attributes != null).ToArray());
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
                var info = _fileSystem.GetInfo(path) ?? throw Own(new FileNotFoundException($"No such file: {path}"));
                return ToAttributes(info);
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
                if (_fileSystem.GetInfo(path) == null)
                    throw Own(new FileNotFoundException($"No such file: {path}"));
                ApplyAttributes(path, attributes, stream: null);
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
                if (_fileSystem.DirectoryExists(path))
                    throw Own(new UnauthorizedAccessException($"Is a directory, use RMDIR: {path}"));
                if (!_fileSystem.RemoveFile(path))
                    throw Own(new FileNotFoundException($"No such file: {path}"));
            }
            catch (Exception ex)
            {
                throw Translate(ex, path);
            }
        }

        public void Rename(string oldPath, string newPath)
        {
            _logger.LogInformation("User {Username} renames {OldPath} to {NewPath}.", _username, oldPath, newPath);
            try
            {
                if (_fileSystem.GetInfo(oldPath) == null)
                    throw Own(new FileNotFoundException($"No such file: {oldPath}"));
                if (_fileSystem.GetInfo(newPath) != null)
                    throw Own(new IOException($"The target already exists: {newPath}")); // SFTP v3: RENAME does not overwrite
                if (!_fileSystem.MoveFileOrDirectory(oldPath, newPath))
                    throw Own(new IOException($"Cannot rename {oldPath} to {newPath}."));
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
                _fileSystem.RenameReplacing(oldPath, newPath);
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
                var space = _fileSystem.GetStorageSpace(path)
                    ?? throw Own(new IOException($"The storage space is not known: {path}"));
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

        /// <summary>fsync@openssh.com: writes the data of an open file to the storage.</summary>
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
                if (_fileSystem.GetInfo(path) != null)
                    throw Own(new IOException($"Already exists: {path}"));
                if (!_fileSystem.DirectoryExists(path + "/.."))
                    throw Own(new DirectoryNotFoundException($"No such directory: {path}/.."));
                if (!_fileSystem.MakeDirectory(path))
                    throw Own(new IOException($"Cannot create the directory {path}."));
                if (attributes?.Permissions is { } permissions)
                    _fileSystem.SetPermissions(path, permissions);
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
                if (!_fileSystem.DirectoryExists(path))
                {
                    if (_fileSystem.FileExists(path))
                        throw Own(new IOException($"Not a directory: {path}"));
                    throw Own(new DirectoryNotFoundException($"No such directory: {path}"));
                }
                if (!_fileSystem.RemoveDirectory(path))
                    throw Own(new UnauthorizedAccessException($"Cannot remove the directory {path}."));
            }
            catch (Exception ex)
            {
                throw Translate(ex, path);
            }
        }

        private SftpFileEntry Entry(string name, string path)
        {
            FileSystemEntryInfo info;
            try
            {
                info = _fileSystem.GetInfo(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                info = null; // for example removed after the listing
            }
            return new SftpFileEntry { FileName = name, Attributes = info == null ? null : ToAttributes(info) };
        }

        private static SftpFileAttributes ToAttributes(FileSystemEntryInfo info)
        {
            var isDirectory = info.Type == ResourceType.Folder;
            return new SftpFileAttributes
            {
                Size = isDirectory ? null : info.Length,
                Permissions = (isDirectory ? DirectoryType : RegularFileType) | (info.Permissions & 0x1FF),
                AccessTime = ToUnixTime(info.LastAccessUtc),
                ModificationTime = ToUnixTime(info.LastWriteUtc),
            };
        }

        /// <summary>
        /// Applies size, permissions and times (SSH_FXP_SETSTAT and SSH_FXP_FSETSTAT). The uid and gid
        /// are ignored: the server has no user or group ids to give.
        /// </summary>
        private void ApplyAttributes(string path, SftpFileAttributes attributes, Stream stream)
        {
            if (attributes == null)
                return;

            if (attributes.Size is { } size)
            {
                if (size > long.MaxValue)
                    throw Own(new IOException("The size is too large."));
                if (stream != null)
                    stream.SetLength((long)size);
                else
                    _fileSystem.SetFileLength(path, (long)size);
            }

            if (attributes.Permissions is { } permissions)
                _fileSystem.SetPermissions(path, permissions);

            if (attributes.AccessTime != null || attributes.ModificationTime != null)
            {
                stream?.Flush(); // a later flush of buffered data would change the write time again
                _fileSystem.SetTimes(path, FromUnixTime(attributes.AccessTime), FromUnixTime(attributes.ModificationTime));
            }
        }

        private static FileMode MapMode(SftpOpenFlags flags)
        {
            // The engine has already rejected TRUNC or EXCL without CREAT.
            if ((flags & SftpOpenFlags.Create) == 0)
                return FileMode.Open;
            if ((flags & SftpOpenFlags.Exclusive) != 0)
                return FileMode.CreateNew;
            if ((flags & SftpOpenFlags.Truncate) != 0)
                return FileMode.Create;
            return FileMode.OpenOrCreate;
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
        /// Replaces an exception of the file system with one of the same kind for the engine, with only the
        /// virtual path in its message. The original exception, which can contain the physical path, is
        /// logged here: at debug level when a client can cause it (missing path, denied access, I/O error
        /// such as an existing target), at error level otherwise. An unexpected exception becomes an
        /// <see cref="InvalidOperationException"/>, which the engine answers with SSH_FX_FAILURE and logs as
        /// an error.
        /// </summary>
        private Exception Translate(Exception ex, string path)
        {
            if (ex.Data.Contains(OwnExceptionKey))
                return ex;

            if (ex is IOException or UnauthorizedAccessException or ArgumentException)
                _logger.LogDebug(ex, "SFTP operation of user {Username} on {Path} failed.", _username, path);
            else
                _logger.LogError(ex, "SFTP operation of user {Username} on {Path} failed unexpectedly.", _username, path);

            return ex switch
            {
                FileNotFoundException => Own(new FileNotFoundException($"No such file: {path}")),
                DirectoryNotFoundException => Own(new DirectoryNotFoundException($"No such file: {path}")),
                UnauthorizedAccessException => Own(new UnauthorizedAccessException($"Permission denied: {path}")),
                ArgumentException => Own(new ArgumentException($"Bad request: {path}")),
                IOException => Own(new IOException($"Failure: {path}")),
                _ => Own(new InvalidOperationException($"Internal error: {path}")),
            };
        }

        private sealed class FileHandle : ISftpFileHandle
        {
            private readonly SftpFileSystemAdapter _owner;
            private readonly Stream _stream;
            private readonly string _path;
            private readonly bool _append;
            private bool _disposed;

            public FileHandle(SftpFileSystemAdapter owner, Stream stream, string path, bool append)
            {
                _owner = owner;
                _stream = stream;
                _path = path;
                _append = append;
            }

            public int Read(long offset, Span<byte> buffer)
            {
                try
                {
                    _stream.Position = offset;
                    return _stream.Read(buffer);
                }
                catch (Exception ex)
                {
                    throw _owner.Translate(ex, _path);
                }
            }

            public void Write(long offset, ReadOnlySpan<byte> data)
            {
                try
                {
                    // SSH_FXF_APPEND: every write goes to the end of the file.
                    _stream.Position = _append ? _stream.Length : offset;
                    _stream.Write(data);
                }
                catch (Exception ex)
                {
                    throw _owner.Translate(ex, _path);
                }
            }

            public SftpFileAttributes GetAttributes()
            {
                try
                {
                    var info = _owner._fileSystem.GetInfo(_path);
                    var attributes = info != null && info.Type == ResourceType.File
                        ? ToAttributes(info)
                        : new SftpFileAttributes { Permissions = RegularFileType | 0x1A4 }; // removed or replaced while open
                    attributes.Size = (ulong)_stream.Length; // includes data that is not flushed yet
                    return attributes;
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
                    _owner.ApplyAttributes(_path, attributes, _stream);
                }
                catch (Exception ex)
                {
                    throw _owner.Translate(ex, _path);
                }
            }

            /// <summary>
            /// Writes the buffered data to the storage. A <see cref="FileStream"/> flushes to the disk (fsync);
            /// another stream flushes to its backend.
            /// </summary>
            public void Sync()
            {
                try
                {
                    if (_stream is FileStream fileStream)
                        fileStream.Flush(flushToDisk: true);
                    else
                        _stream.Flush();
                }
                catch (Exception ex)
                {
                    throw _owner.Translate(ex, _path);
                }
            }

            /// <summary>
            /// Flushes and closes the file. A failed flush (for example a full disk) is reported to the
            /// client in the CLOSE status, and the file is closed in all cases.
            /// </summary>
            public void Dispose()
            {
                if (_disposed)
                    return;
                _disposed = true;

                try
                {
                    _stream.Flush();
                }
                catch (Exception ex)
                {
                    try { _stream.Dispose(); } catch (Exception) { /* the flush error is reported */ }
                    throw _owner.Translate(ex, _path);
                }
                _stream.Dispose();
            }
        }

        private sealed class DirectoryHandle : ISftpDirectoryHandle
        {
            private readonly SftpFileEntry[] _entries;
            private int _next;

            public DirectoryHandle(SftpFileEntry[] entries)
            {
                _entries = entries;
            }

            public SftpFileEntry[] ReadEntries(int maxCount)
            {
                var count = Math.Min(maxCount, _entries.Length - _next);
                if (count <= 0)
                    return Array.Empty<SftpFileEntry>();

                var batch = _entries.AsSpan(_next, count).ToArray();
                _next += count;
                return batch;
            }

            public void Dispose()
            {
            }
        }
    }
}
