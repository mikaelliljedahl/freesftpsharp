using SshServer.Interfaces;
using SshServer.Interfaces.Storage;
using System.IO;
using System.Runtime.CompilerServices;

namespace SshServer.Filesystem.LocalDisk
{
    /// <summary>
    /// Gives an SFTP user access to one directory on the local disk.
    /// All paths that this class receives are virtual paths, where "/" is the user root directory.
    /// A virtual path can never point to a location outside the user root directory, also not through a
    /// symbolic link or junction inside the root: a path whose real path (all links followed) is outside
    /// the real path of the root is refused with <see cref="FileSystemError.PermissionDenied"/>. Links whose
    /// targets stay inside the root work. The user root itself can be a link.
    /// </summary>
    public class LocalFileSystem : IFileSystem
    {
        private static readonly StringComparison PathComparison =
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

        private readonly string _userRootDirectory;

        public LocalFileSystem(string userRootDirectory)
        {
            if (string.IsNullOrWhiteSpace(userRootDirectory))
                throw new ArgumentException("The user root directory is not set.", nameof(userRootDirectory));

            _userRootDirectory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(userRootDirectory));
        }

        /// <summary>
        /// Converts a virtual path to a full path on the local disk. Throws <see cref="FileSystemException"/> with
        /// <see cref="FileSystemError.PermissionDenied"/> if the result is outside the user root directory, and with
        /// <see cref="FileSystemError.Failure"/> for a link loop.
        /// </summary>
        public string GetPhysicalPath(string? virtualPath)
        {
            var relativePath = VirtualPath.Normalize(virtualPath).TrimStart('/');
            var fullPath = relativePath.Length == 0
                ? _userRootDirectory
                : Path.GetFullPath(Path.Join(_userRootDirectory, relativePath));

            // Second line of defence: the normalization above must already prevent this.
            // The check also catches platform rules, for example Windows that removes trailing dots and spaces.
            if (!IsInside(fullPath, _userRootDirectory))
                throw new FileSystemException(FileSystemError.PermissionDenied, $"The path is outside the user root directory: {virtualPath}");

            // The path is inside the root as text, but a symbolic link or junction on the way (or the last
            // segment itself) can point outside it. Follow the links like the operating system does and
            // check the real path against the real path of the root.
            if (!string.Equals(fullPath, _userRootDirectory, PathComparison))
            {
                var realRoot = ResolveLinks(_userRootDirectory);
                var realPath = ResolveLinks(fullPath);
                if (!IsInside(realPath, realRoot))
                    throw new FileSystemException(FileSystemError.PermissionDenied, $"The path is a link to outside the user root directory: {virtualPath}");
            }

            return fullPath;
        }

        /// <summary>
        /// True if a physical path from <see cref="GetPhysicalPath"/> is the user root directory, also when a
        /// link in a parent directory leads to it (for example "/link-to-parent/root"). A path whose last
        /// segment is itself a link to the root is not the root: removing or moving it changes only the link.
        /// </summary>
        private bool IsUserRoot(string physicalPath)
        {
            if (string.Equals(physicalPath, _userRootDirectory, PathComparison))
                return true;

            var parent = Path.GetDirectoryName(physicalPath);
            if (parent == null)
                return false;
            var realPath = Path.Join(ResolveLinks(parent), Path.GetFileName(physicalPath));
            return string.Equals(realPath, ResolveLinks(_userRootDirectory), PathComparison);
        }

        private static bool IsInside(string path, string root)
        {
            var prefix = Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar;
            return string.Equals(path, root, PathComparison) || path.StartsWith(prefix, PathComparison);
        }

        /// <summary>
        /// The most symbolic links that one path can pass through, like MAXSYMLINKS (40) on Linux.
        /// </summary>
        private const int MaxLinks = 40;

        /// <summary>
        /// Returns the real path of an absolute path: every symbolic link or junction in it, also in the
        /// targets of links, is replaced by its target, and "." and ".." are removed. Segments that do not
        /// exist are kept as they are (a path to a new file has a last segment that does not exist).
        /// <para>
        /// A ".." segment in a link target goes to the parent of the real directory on Linux and macOS
        /// (POSIX), and is removed as text on Windows, which also removes it as text before it follows a link.
        /// </para>
        /// </summary>
        private static string ResolveLinks(string path)
        {
            var linkCount = 0;
            return ResolveLinks(path, ref linkCount);
        }

        private static string ResolveLinks(string path, ref int linkCount)
        {
            if (OperatingSystem.IsWindows())
                path = Path.GetFullPath(path);

            var root = Path.GetPathRoot(path) ?? string.Empty;
            var current = root;
            var segments = path.Substring(root.Length).Split(
                [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries);

            foreach (var segment in segments)
            {
                if (segment == ".")
                    continue;
                if (segment == "..")
                {
                    current = Path.GetDirectoryName(current) ?? current;
                    continue;
                }

                var candidate = Path.Join(current, segment);
                var target = GetLinkTarget(candidate);
                if (target == null)
                {
                    current = candidate;
                    continue;
                }

                if (++linkCount > MaxLinks)
                    throw new FileSystemException(FileSystemError.Failure, "Too many levels of symbolic links.");

                // A relative target is relative to the directory that has the link.
                var targetPath = OperatingSystem.IsWindows()
                    ? Path.GetFullPath(WithoutDevicePrefix(target), current)
                    : Path.IsPathRooted(target) ? target : Path.Join(current, target);
                current = ResolveLinks(targetPath, ref linkCount);
            }

            return current;
        }

        /// <summary>
        /// Windows: a junction can store its target as "\\?\C:\dir" or "\??\C:\dir". Returns the normal
        /// form "C:\dir" (or "\\server\share" for "\\?\UNC\server\share"), so it compares with the root.
        /// </summary>
        private static string WithoutDevicePrefix(string target)
        {
            foreach (var prefix in new[] { @"\\?\", @"\??\" })
            {
                if (!target.StartsWith(prefix, StringComparison.Ordinal))
                    continue;
                var rest = target.Substring(prefix.Length);
                if (rest.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase))
                    return @"\\" + rest.Substring(4);
                if (rest.Length >= 2 && char.IsAsciiLetter(rest[0]) && rest[1] == ':')
                    return rest;
            }
            return target;
        }

        /// <summary>The target of a symbolic link or junction as stored in the link, or null if the path is not a link or does not exist.</summary>
        private static string? GetLinkTarget(string path)
        {
            try
            {
                return new FileInfo(path).LinkTarget;
            }
            catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
            {
                return null;
            }
        }

        private static uint GetPermissions(FileSystemInfo info)
        {
            if (!OperatingSystem.IsWindows())
                return (uint)info.UnixFileMode & 0x1FF;

            if (info is DirectoryInfo)
                return 0x1ED; // rwxr-xr-x
            return ((FileInfo)info).IsReadOnly ? 0x124u : 0x1A4u; // r--r--r-- or rw-r--r--
        }

        // ---- IFileSystem ----

        /// <summary>
        /// Everything except symbolic links (links are followed and checked, never reported or created) and server-side
        /// copy. On Windows only the owner write bit of the permissions is applied (read-only file).
        /// </summary>
        public StorageCapabilities Capabilities =>
            StorageCapabilities.RandomAccessWrite | StorageCapabilities.Append | StorageCapabilities.Rename
            | StorageCapabilities.SetTimes | StorageCapabilities.SetPermissions
            | (OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StorageCapabilities.CaseInsensitivePaths : StorageCapabilities.None);

        // The local disk is fast and FileStream does synchronous I/O, so every member completes synchronously and
        // returns a completed ValueTask: no thread pool hop per SFTP request, and the synchronous SFTP bridge
        // (SftpFileSystemAdapter) never blocks a thread on it.

        public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Run(path, () => GetEntry(GetPhysicalPath(path), VirtualPath.GetName(VirtualPath.Normalize(path)))));
        }

        public async IAsyncEnumerable<FileSystemEntry> ListAsync(string path, [EnumeratorCancellation] CancellationToken ct)
        {
            await Task.CompletedTask; // synchronous enumeration of the directory, one entry per MoveNextAsync
            ct.ThrowIfCancellationRequested();
            var virtualDirectory = VirtualPath.Normalize(path);
            using var entries = Run(path, () =>
            {
                var physicalPath = GetPhysicalPath(virtualDirectory);
                if (!Directory.Exists(physicalPath))
                {
                    if (File.Exists(physicalPath))
                        throw new FileSystemException(FileSystemError.NotADirectory, $"Not a directory: {path}");
                    throw new FileSystemException(FileSystemError.NoSuchFile, $"No such directory: {path}");
                }
                return new DirectoryInfo(physicalPath).EnumerateFileSystemInfos().GetEnumerator();
            });

            while (true)
            {
                ct.ThrowIfCancellationRequested();
                if (!Run(path, entries.MoveNext))
                    yield break;
                if (GetListEntry(virtualDirectory, entries.Current.Name) is { } entry)
                    yield return entry;
            }
        }

        /// <summary>
        /// The entry of a directory listing, or null when the user cannot reach it: a link to outside the root, a link
        /// loop, or an entry that was removed after the listing.
        /// </summary>
        private FileSystemEntry? GetListEntry(string virtualDirectory, string name)
        {
            try
            {
                return GetEntry(GetPhysicalPath(VirtualPath.Combine(virtualDirectory, name)), name);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FileSystemException)
            {
                return null;
            }
        }

        public ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Run<IFileHandle>(path, () =>
            {
                var physicalPath = GetPhysicalPath(path);
                if (Directory.Exists(physicalPath))
                    throw new FileSystemException(FileSystemError.IsADirectory, $"Is a directory: {path}");

                var create = (flags & FileOpenFlags.Create) != 0;
                var exists = File.Exists(physicalPath);
                if (create && exists && (flags & FileOpenFlags.Exclusive) != 0)
                    throw new FileSystemException(FileSystemError.AlreadyExists, $"Already exists: {path}");
                if (!exists)
                    RequireParentDirectory(physicalPath, path);

                var access = default(FileAccess);
                if ((flags & FileOpenFlags.Read) != 0) access |= FileAccess.Read;
                if ((flags & FileOpenFlags.Write) != 0) access |= FileAccess.Write;
                if (access == default)
                    throw new FileSystemException(FileSystemError.Failure, $"Open for neither reading nor writing: {path}");

                var stream = new FileStream(physicalPath, OpenMode(flags), access, FileShare.ReadWrite | FileShare.Delete);
                try
                {
                    if (create && !exists && initial?.Permissions is { } permissions)
                        ApplyPermissions(physicalPath, permissions, path);
                }
                catch
                {
                    stream.Dispose();
                    throw;
                }
                return new LocalFileHandle(this, stream, path, flags);
            }));
        }

        private static FileMode OpenMode(FileOpenFlags flags)
        {
            if ((flags & FileOpenFlags.Create) == 0)
                return FileMode.Open;
            if ((flags & FileOpenFlags.Exclusive) != 0)
                return FileMode.CreateNew;
            if ((flags & FileOpenFlags.Truncate) != 0)
                return FileMode.Create;
            return FileMode.OpenOrCreate;
        }

        public ValueTask CreateDirectoryAsync(string path, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Run(path, () =>
            {
                var physicalPath = GetPhysicalPath(path);
                if (Directory.Exists(physicalPath) || File.Exists(physicalPath))
                    throw new FileSystemException(FileSystemError.AlreadyExists, $"Already exists: {path}");
                RequireParentDirectory(physicalPath, path);
                Directory.CreateDirectory(physicalPath);
            });
            return ValueTask.CompletedTask;
        }

        public ValueTask DeleteFileAsync(string path, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Run(path, () =>
            {
                var physicalPath = GetPhysicalPath(path);
                if (Directory.Exists(physicalPath))
                    throw new FileSystemException(FileSystemError.IsADirectory, $"Is a directory: {path}");
                if (!File.Exists(physicalPath))
                    throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");
                File.Delete(physicalPath);
            });
            return ValueTask.CompletedTask;
        }

        public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Run(path, () =>
            {
                var physicalPath = GetPhysicalPath(path);
                if (IsUserRoot(physicalPath))
                    throw new FileSystemException(FileSystemError.PermissionDenied, "The user root directory cannot be removed.");
                if (!Directory.Exists(physicalPath))
                {
                    if (File.Exists(physicalPath))
                        throw new FileSystemException(FileSystemError.NotADirectory, $"Not a directory: {path}");
                    throw new FileSystemException(FileSystemError.NoSuchFile, $"No such directory: {path}");
                }

                // A link to a directory is removed as a link; the directory it points to (maybe the root) stays.
                if (GetLinkTarget(physicalPath) == null && Directory.EnumerateFileSystemEntries(physicalPath).Any())
                    throw new FileSystemException(FileSystemError.DirectoryNotEmpty, $"The directory is not empty: {path}");
                Directory.Delete(physicalPath);
            });
            return ValueTask.CompletedTask;
        }

        public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Run(oldPath, () =>
            {
                var source = GetPhysicalPath(oldPath);
                var target = GetPhysicalPath(newPath);
                if (IsUserRoot(source) || IsUserRoot(target))
                    throw new FileSystemException(FileSystemError.PermissionDenied, "The user root directory cannot be moved or replaced.");

                var isDirectory = Directory.Exists(source);
                if (!isDirectory && !File.Exists(source))
                    throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {oldPath}");
                RequireParentDirectory(target, newPath);
                if (string.Equals(source, target, StringComparison.Ordinal))
                    return; // rename(2) of a path to itself does nothing

                var targetIsDirectory = Directory.Exists(target);
                if (targetIsDirectory || File.Exists(target))
                {
                    if ((flags & RenameFlags.ReplaceExisting) == 0 || isDirectory)
                        throw new FileSystemException(FileSystemError.AlreadyExists, $"The target already exists: {newPath}");
                    if (targetIsDirectory)
                        throw new FileSystemException(FileSystemError.IsADirectory, $"The target is a directory: {newPath}");
                }

                if (isDirectory)
                    Directory.Move(source, target);
                else
                    // One rename(2) on Unix and MoveFileEx(MOVEFILE_REPLACE_EXISTING) on Windows: the target is
                    // replaced atomically, a reader sees either the old or the new file.
                    File.Move(source, target, overwrite: (flags & RenameFlags.ReplaceExisting) != 0);
            });
            return ValueTask.CompletedTask;
        }

        public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Run(path, () =>
            {
                var physicalPath = GetPhysicalPath(path);
                var isDirectory = Directory.Exists(physicalPath);
                if (!isDirectory && !File.Exists(physicalPath))
                    throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");

                if (update.Size is { } size)
                {
                    if (isDirectory)
                        throw new FileSystemException(FileSystemError.IsADirectory, $"Is a directory: {path}");
                    using var stream = new FileStream(physicalPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                    stream.SetLength(size);
                }
                ApplyPermissionsAndTimes(physicalPath, update, path);
            });
            return ValueTask.CompletedTask;
        }

        public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Run(path, () =>
            {
                var physicalPath = GetPhysicalPath(path);
                if (!Directory.Exists(physicalPath) && !File.Exists(physicalPath))
                    throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");

                try
                {
                    // On Unix DriveInfo takes any path (statvfs); on Windows it needs the drive root.
                    var drive = new DriveInfo(OperatingSystem.IsWindows() ? Path.GetPathRoot(physicalPath)! : physicalPath);
                    return new StorageSpace((ulong)drive.TotalSize, (ulong)drive.TotalFreeSpace, (ulong)drive.AvailableFreeSpace);
                }
                catch (ArgumentException)
                {
                    return (StorageSpace?)null; // for example a UNC path on Windows
                }
            }));
        }

        /// <summary>The entry of an existing physical path (links followed), or null when it does not exist.</summary>
        private static FileSystemEntry? GetEntry(string physicalPath, string name)
        {
            var dir = new DirectoryInfo(physicalPath);
            if (dir.Exists)
                return new FileSystemEntry(name, FileSystemEntryType.Directory, 0, dir.LastWriteTimeUtc, dir.LastAccessTimeUtc) { Permissions = GetPermissions(dir) };

            var file = new FileInfo(physicalPath);
            if (file.Exists)
                return new FileSystemEntry(name, FileSystemEntryType.File, file.Length, file.LastWriteTimeUtc, file.LastAccessTimeUtc) { Permissions = GetPermissions(file) };

            return null;
        }

        /// <summary>The parent of a new entry must be a directory (like ENOENT and ENOTDIR of POSIX, both NoSuchFile).</summary>
        private static void RequireParentDirectory(string physicalPath, string path)
        {
            var parent = Path.GetDirectoryName(physicalPath);
            if (parent != null && !Directory.Exists(parent))
                throw new FileSystemException(FileSystemError.NoSuchFile, $"No such directory: {path}/..");
        }

        /// <summary>Applies the permissions, then the times of an update to an existing file or directory.</summary>
        private void ApplyPermissionsAndTimes(string physicalPath, FileAttributesUpdate update, string path)
        {
            if (update.Permissions is { } permissions)
                ApplyPermissions(physicalPath, permissions, path);

            if (update.HasTimes)
            {
                FileSystemInfo info = Directory.Exists(physicalPath) ? new DirectoryInfo(physicalPath) : new FileInfo(physicalPath);
                if (update.LastAccessTimeUtc is { } accessed)
                    info.LastAccessTimeUtc = accessed;
                if (update.LastWriteTimeUtc is { } written)
                    info.LastWriteTimeUtc = written;
            }
        }

        private void ApplyPermissions(string physicalPath, uint mode, string path)
        {
            if (IsUserRoot(physicalPath))
                throw new FileSystemException(FileSystemError.PermissionDenied, "The permissions of the user root directory cannot be changed.");

            if (Directory.Exists(physicalPath))
            {
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(physicalPath, (UnixFileMode)(mode & 0x1FF));
                return; // Windows has no permissions for a directory that we can map
            }

            var file = new FileInfo(physicalPath);
            if (!file.Exists)
                throw new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}");

            if (OperatingSystem.IsWindows())
                file.IsReadOnly = (mode & 0x80) == 0; // like Win32-OpenSSH: no owner write bit gives a read-only file
            else
                File.SetUnixFileMode(physicalPath, (UnixFileMode)(mode & 0x1FF));
        }

        private static void Run(string path, Action operation) => Run(path, () => { operation(); return true; });

        /// <summary>
        /// Runs an operation of the local disk and translates its <c>System.IO</c> exceptions to
        /// <see cref="FileSystemException"/> with the virtual path. Other exceptions are bugs and stay as they are.
        /// </summary>
        private static T Run<T>(string path, Func<T> operation)
        {
            try
            {
                return operation();
            }
            catch (Exception ex) when (Translate(ex, path) is { } translated)
            {
                throw translated;
            }
        }

        private static FileSystemException? Translate(Exception ex, string path) => ex switch
        {
            FileSystemException own => own,
            FileNotFoundException or DirectoryNotFoundException => new FileSystemException(FileSystemError.NoSuchFile, $"No such file: {path}", ex),
            UnauthorizedAccessException => new FileSystemException(FileSystemError.PermissionDenied, $"Permission denied: {path}", ex),
            IOException => new FileSystemException(FileSystemError.Failure, $"Failure: {path}", ex),
            ArgumentException or NotSupportedException => new FileSystemException(FileSystemError.InvalidPath, $"Invalid path: {path}", ex),
            _ => null,
        };

        /// <summary>An open file on the local disk. Positional I/O on one <see cref="FileStream"/>.</summary>
        private sealed class LocalFileHandle(LocalFileSystem owner, FileStream stream, string path, FileOpenFlags flags) : IFileHandle
        {
            private bool _disposed;

            public ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken ct)
            {
                ct.ThrowIfCancellationRequested();
                Check(FileOpenFlags.Read);
                return ValueTask.FromResult(Run(path, () =>
                {
                    stream.Position = offset;
                    return stream.Read(buffer.Span);
                }));
            }

            public ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct)
            {
                ct.ThrowIfCancellationRequested();
                Check(FileOpenFlags.Write);
                Run(path, () =>
                {
                    // FileOpenFlags.Append: every write goes to the end of the file.
                    stream.Position = (flags & FileOpenFlags.Append) != 0 ? stream.Length : offset;
                    stream.Write(data.Span);
                });
                return ValueTask.CompletedTask;
            }

            public ValueTask FlushAsync(CancellationToken ct)
            {
                ct.ThrowIfCancellationRequested();
                Check(FileOpenFlags.None);
                Run(path, () => stream.Flush(flushToDisk: true));
                return ValueTask.CompletedTask;
            }

            /// <summary>The attributes of the open file itself (fstat), also when its path was removed or replaced.</summary>
            public ValueTask<FileSystemEntry> StatAsync(CancellationToken ct)
            {
                ct.ThrowIfCancellationRequested();
                Check(FileOpenFlags.None);
                return ValueTask.FromResult(Run(path, () =>
                {
                    var handle = stream.SafeFileHandle;
                    var permissions = OperatingSystem.IsWindows()
                        ? ((File.GetAttributes(handle) & FileAttributes.ReadOnly) != 0 ? 0x124u : 0x1A4u)
                        : (uint)File.GetUnixFileMode(handle) & 0x1FF;
                    // The length includes the data that is not flushed yet.
                    return new FileSystemEntry(VirtualPath.GetName(VirtualPath.Normalize(path)), FileSystemEntryType.File, stream.Length,
                        File.GetLastWriteTimeUtc(handle), File.GetLastAccessTimeUtc(handle)) { Permissions = permissions };
                }));
            }

            public ValueTask SetAttributesAsync(FileAttributesUpdate update, CancellationToken ct)
            {
                ct.ThrowIfCancellationRequested();
                Check(FileOpenFlags.None);
                Run(path, () =>
                {
                    if (update.Size is { } size)
                        stream.SetLength(size);
                    if (update.HasTimes)
                        stream.Flush(); // a later flush of buffered data would change the write time again
                    if (update.Permissions != null || update.HasTimes)
                        owner.ApplyPermissionsAndTimes(owner.GetPhysicalPath(path), update, path);
                });
                return ValueTask.CompletedTask;
            }

            /// <summary>
            /// Flushes and closes the file. A failed flush (for example a full disk) is thrown, and the file is closed
            /// in all cases.
            /// </summary>
            public ValueTask DisposeAsync()
            {
                if (_disposed)
                    return ValueTask.CompletedTask;
                _disposed = true;

                try
                {
                    Run(path, stream.Flush);
                }
                finally
                {
                    try { stream.Dispose(); } catch (IOException) { /* the flush error, if any, is reported */ }
                }
                return ValueTask.CompletedTask;
            }

            private void Check(FileOpenFlags access)
            {
                if (_disposed)
                    throw new FileSystemException(FileSystemError.Failure, $"The file is closed: {path}");
                if ((flags & access) != access)
                    throw new FileSystemException(FileSystemError.PermissionDenied, $"The file is not open for {access}: {path}");
            }
        }

    }
}
