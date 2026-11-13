using SshServer.Interfaces;
using System.IO;

namespace SshServer.Filesystem.LocalDisk
{
    /// <summary>
    /// Gives an SFTP user access to one directory on the local disk.
    /// All paths that this class receives are virtual paths, where "/" is the user root directory.
    /// A virtual path can never point to a location outside the user root directory.
    /// </summary>
    public class LocalFileSystem : IFileSystem
    {
        private static readonly StringComparison PathComparison =
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

        private readonly string _userRootDirectory;
        private readonly string _userRootPrefix;

        public LocalFileSystem(string userRootDirectory)
        {
            if (string.IsNullOrWhiteSpace(userRootDirectory))
                throw new ArgumentException("The user root directory is not set.", nameof(userRootDirectory));

            _userRootDirectory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(userRootDirectory));
            _userRootPrefix = Path.EndsInDirectorySeparator(_userRootDirectory)
                ? _userRootDirectory
                : _userRootDirectory + Path.DirectorySeparatorChar;
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
            if (!string.Equals(fullPath, _userRootDirectory, PathComparison)
                && !fullPath.StartsWith(_userRootPrefix, PathComparison))
            {
                throw new UnauthorizedAccessException($"The path is outside the user root directory: {virtualPath}");
            }

            return fullPath;
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
            if (string.Equals(absolutepath, _userRootDirectory, PathComparison))
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

                if (string.Equals(oldpathAbsolute, _userRootDirectory, PathComparison))
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

        private static string CombineVirtualPath(string virtualDirectory, string name)
        {
            return virtualDirectory == "/" ? "/" + name : virtualDirectory + "/" + name;
        }
    }
}
