using SshServer.Interfaces;
using System.IO;

namespace SshServer.Filesystem.LocalDisk
{
    /// <summary>
    /// Gives an SFTP user access to one directory on the local disk.
    /// All paths that this class receives are virtual paths, where "/" is the user root directory.
    /// A virtual path can never point to a location outside the user root directory, also not through a
    /// symbolic link or junction inside the root: a path whose real path (all links followed) is outside
    /// the real path of the root is refused with <see cref="UnauthorizedAccessException"/>. Links whose
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
        /// Converts a path from the client to a normalized virtual path that starts with "/".
        /// Both "/" and "\" are separators. "." segments are removed. A ".." segment removes
        /// the previous segment, and a ".." segment at the root stays at the root.
        /// </summary>
        public static string NormalizeVirtualPath(string? path)
        {
            var segments = new List<string>();
            foreach (var segment in (path ?? string.Empty).Split('/', '\\'))
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

        /// <summary>
        /// Converts a virtual path to a full path on the local disk.
        /// Throws <see cref="UnauthorizedAccessException"/> if the result is outside the user root directory.
        /// </summary>
        public string GetPhysicalPath(string? virtualPath)
        {
            var relativePath = NormalizeVirtualPath(virtualPath).TrimStart('/');
            var fullPath = relativePath.Length == 0
                ? _userRootDirectory
                : Path.GetFullPath(Path.Join(_userRootDirectory, relativePath));

            // Second line of defence: the normalization above must already prevent this.
            // The check also catches platform rules, for example Windows that removes trailing dots and spaces.
            if (!IsInside(fullPath, _userRootDirectory))
                throw new UnauthorizedAccessException($"The path is outside the user root directory: {virtualPath}");

            // The path is inside the root as text, but a symbolic link or junction on the way (or the last
            // segment itself) can point outside it. Follow the links like the operating system does and
            // check the real path against the real path of the root.
            if (!string.Equals(fullPath, _userRootDirectory, PathComparison))
            {
                var realRoot = ResolveLinks(_userRootDirectory);
                var realPath = ResolveLinks(fullPath);
                if (!IsInside(realPath, realRoot))
                    throw new UnauthorizedAccessException($"The path is a link to outside the user root directory: {virtualPath}");
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
                    throw new IOException("Too many levels of symbolic links.");

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

        public bool DirectoryExists(string path)
        {
            return new DirectoryInfo(GetPhysicalPath(path)).Exists;
        }

        public bool FileExists(string path)
        {
            return new FileInfo(GetPhysicalPath(path)).Exists;
        }

        public IEnumerable<Resource> GetFiles(string path)
        {
            var virtualDirectory = NormalizeVirtualPath(path);
            var di = new DirectoryInfo(GetPhysicalPath(virtualDirectory));

            var foundfiles = new List<Resource>();
            foreach (var file in di.GetFiles())
            {
                foundfiles.Add(new Resource
                {
                    Type = ResourceType.File,
                    FullName = CombineVirtualPath(virtualDirectory, file.Name),
                    Length = (ulong)file.Length,
                    Name = file.Name
                });
            }

            return foundfiles;
        }

        public IEnumerable<Resource> GetDirectories(string path)
        {
            var virtualDirectory = NormalizeVirtualPath(path);
            var di = new DirectoryInfo(GetPhysicalPath(virtualDirectory));

            var foundDirs = new List<Resource>();
            foreach (var dir in di.GetDirectories())
            {
                foundDirs.Add(new Resource
                {
                    Type = ResourceType.Folder,
                    FullName = CombineVirtualPath(virtualDirectory, dir.Name),
                    Length = 0,
                    Name = dir.Name
                });
            }

            if (virtualDirectory != "/")
            {
                // If not on root level, add the parent too. The parent is always inside the user root directory.
                foundDirs.Add(new Resource
                {
                    Type = ResourceType.Folder,
                    FullName = NormalizeVirtualPath(virtualDirectory + "/.."),
                    Length = 0,
                    Name = ".."
                });
            }

            return foundDirs;
        }

        public ulong GetSize(string path)
        {
            var fi = new FileInfo(GetPhysicalPath(path));
            if (fi.Exists)
                return (ulong)fi.Length;
            return 0;
        }

        public bool MakeDirectory(string newPath)
        {
            try
            {
                new DirectoryInfo(GetPhysicalPath(newPath)).Create();
                return true;
            }
            catch
            {
                return false;
            }
        }

        public Stream OpenStreamRead(string path)
        {
            return new FileInfo(GetPhysicalPath(path)).OpenRead();
        }

        public Stream OpenStreamWrite(string path)
        {
            return OpenStreamWrite(path, FileMode.OpenOrCreate);
        }

        public Stream OpenStreamWrite(string path, FileMode mode)
        {
            return new FileStream(GetPhysicalPath(path), mode, FileAccess.ReadWrite);
        }

        public bool RemoveDirectory(string pathToRemove)
        {
            var absolutepath = GetPhysicalPath(pathToRemove);
            if (IsUserRoot(absolutepath))
                return false; // never remove the user root directory

            var di = new DirectoryInfo(absolutepath);
            var fi = new FileInfo(absolutepath); // Renci SSH uses this command to remove a file too, so we must check if path is a dir or file

            if (fi.Exists)
            {
                fi.Delete();
                return true;
            }

            if (di.Exists)
            {
                di.Delete();
                return true;
            }

            return false;
        }

        public bool RemoveFile(string pathToRemove)
        {
            var fi = new FileInfo(GetPhysicalPath(pathToRemove));

            if (fi.Exists)
            {
                fi.Delete();
                return true;
            }
            return false;
        }

        public bool MoveFileOrDirectory(string oldpath, string newpath)
        {
            try
            {
                var oldpathAbsolute = GetPhysicalPath(oldpath);
                var newpathAbsolute = GetPhysicalPath(newpath);

                if (IsUserRoot(oldpathAbsolute))
                    return false; // never move the user root directory

                var di = new DirectoryInfo(oldpathAbsolute);
                if (di.Exists)
                {
                    di.MoveTo(newpathAbsolute);
                    return true;
                }

                var fi = new FileInfo(oldpathAbsolute);
                if (fi.Exists)
                {
                    fi.MoveTo(newpathAbsolute);
                    return true;
                }
            }
            catch
            {
                return false;
            }
            return false;
        }

        public DateTime GetDirectoryLastModified(string path)
        {
            return new DirectoryInfo(GetPhysicalPath(path)).LastWriteTimeUtc;
        }

        public DateTime GetDirectoryLastAccessed(string path)
        {
            return new DirectoryInfo(GetPhysicalPath(path)).LastAccessTimeUtc;
        }

        public DateTime GetFileLastModified(string path)
        {
            return new FileInfo(GetPhysicalPath(path)).LastWriteTimeUtc;
        }

        public DateTime GetFileLastAccessed(string path)
        {
            return new FileInfo(GetPhysicalPath(path)).LastAccessTimeUtc;
        }

        public FileSystemEntryInfo? GetInfo(string path)
        {
            var physicalPath = GetPhysicalPath(path);

            var dir = new DirectoryInfo(physicalPath);
            if (dir.Exists)
                return new FileSystemEntryInfo(ResourceType.Folder, 0, dir.LastAccessTimeUtc, dir.LastWriteTimeUtc, GetPermissions(dir));

            var file = new FileInfo(physicalPath);
            if (file.Exists)
                return new FileSystemEntryInfo(ResourceType.File, (ulong)file.Length, file.LastAccessTimeUtc, file.LastWriteTimeUtc, GetPermissions(file));

            return null;
        }

        private static uint GetPermissions(FileSystemInfo info)
        {
            if (!OperatingSystem.IsWindows())
                return (uint)info.UnixFileMode & 0x1FF;

            if (info is DirectoryInfo)
                return 0x1ED; // rwxr-xr-x
            return ((FileInfo)info).IsReadOnly ? 0x124u : 0x1A4u; // r--r--r-- or rw-r--r--
        }

        public Stream OpenFile(string path, FileMode mode, FileAccess access)
        {
            return new FileStream(GetPhysicalPath(path), mode, access, FileShare.ReadWrite | FileShare.Delete);
        }

        public void SetFileLength(string path, long length)
        {
            using var stream = new FileStream(GetPhysicalPath(path), FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            stream.SetLength(length);
        }

        public void SetTimes(string path, DateTime? lastAccessUtc, DateTime? lastWriteUtc)
        {
            var physicalPath = GetPhysicalPath(path);
            FileSystemInfo info = Directory.Exists(physicalPath) ? new DirectoryInfo(physicalPath) : new FileInfo(physicalPath);
            if (!info.Exists)
                throw new FileNotFoundException($"No such file: {path}");

            if (lastAccessUtc is { } accessed)
                info.LastAccessTimeUtc = accessed;
            if (lastWriteUtc is { } written)
                info.LastWriteTimeUtc = written;
        }

        public void SetPermissions(string path, uint mode)
        {
            var physicalPath = GetPhysicalPath(path);
            if (IsUserRoot(physicalPath))
                throw new UnauthorizedAccessException("The permissions of the user root directory cannot be changed.");

            if (Directory.Exists(physicalPath))
            {
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(physicalPath, (UnixFileMode)(mode & 0x1FF));
                return; // Windows has no permissions for a directory that we can map
            }

            var file = new FileInfo(physicalPath);
            if (!file.Exists)
                throw new FileNotFoundException($"No such file: {path}");

            if (OperatingSystem.IsWindows())
                file.IsReadOnly = (mode & 0x80) == 0; // like Win32-OpenSSH: no owner write bit gives a read-only file
            else
                File.SetUnixFileMode(physicalPath, (UnixFileMode)(mode & 0x1FF));
        }

        public void RenameReplacing(string oldPath, string newPath)
        {
            var source = GetPhysicalPath(oldPath);
            var target = GetPhysicalPath(newPath);
            if (IsUserRoot(source) || IsUserRoot(target))
                throw new UnauthorizedAccessException("The user root directory cannot be moved or replaced.");

            if (Directory.Exists(source))
            {
                if (Directory.Exists(target) || File.Exists(target))
                    throw new IOException($"The target already exists: {newPath}");
                Directory.Move(source, target);
                return;
            }

            if (!File.Exists(source))
                throw new FileNotFoundException($"No such file: {oldPath}");
            if (Directory.Exists(target))
                throw new IOException($"The target is a directory: {newPath}");
            if (string.Equals(source, target, StringComparison.Ordinal))
                return; // rename(2) of a path to itself does nothing

            // One rename(2) on Unix and MoveFileEx(MOVEFILE_REPLACE_EXISTING) on Windows: the target is
            // replaced atomically, a reader sees either the old or the new file.
            File.Move(source, target, overwrite: true);
        }

        public StorageSpace? GetStorageSpace(string path)
        {
            var physicalPath = GetPhysicalPath(path);
            if (!Directory.Exists(physicalPath) && !File.Exists(physicalPath))
                throw new FileNotFoundException($"No such file: {path}");

            try
            {
                // On Unix DriveInfo takes any path (statvfs); on Windows it needs the drive root.
                var drive = new DriveInfo(OperatingSystem.IsWindows() ? Path.GetPathRoot(physicalPath)! : physicalPath);
                return new StorageSpace((ulong)drive.TotalSize, (ulong)drive.TotalFreeSpace, (ulong)drive.AvailableFreeSpace);
            }
            catch (ArgumentException)
            {
                return null; // for example a UNC path on Windows
            }
        }

        private static string CombineVirtualPath(string virtualDirectory, string name)
        {
            return virtualDirectory == "/" ? "/" + name : virtualDirectory + "/" + name;
        }
    }
}
