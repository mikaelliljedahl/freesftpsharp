using SshServer.Interfaces;
using System.IO;
using System.Reflection.Metadata;

namespace SshServer.Filesystem.LocalDisk
{
    public class LocalFileSystem : IFileSystem
    {
        private readonly string _userRootDirectory;

        
        public LocalFileSystem(string userRootDirectory)
        {
            _userRootDirectory = userRootDirectory;
        }

        public bool DirectoryExists(string path)
        {
            var absolutepath = _userRootDirectory + path;
            DirectoryInfo di = new DirectoryInfo(absolutepath);
            return di.Exists;
        }

        public IEnumerable<Resource> GetFiles(string path)
        {
            var absolutepath = _userRootDirectory + path;

            DirectoryInfo diRoot = new DirectoryInfo(_userRootDirectory + "/");
            DirectoryInfo di = new DirectoryInfo(absolutepath);
            //absolutepath = di.FullName.Replace(_userRootDirectory, "/").Replace("\\", "/").Replace("//", "/");

            if (diRoot.Parent?.FullName == di.FullName || diRoot.Parent?.Parent?.FullName == di.FullName)
            {
                di = new DirectoryInfo(_userRootDirectory);
            }

            var foundfiles = new List<Resource>();
            var allfiles = di.GetFiles();

            foreach (var file in allfiles)
            {
                foundfiles.Add(MapFileToResource(new FileInfo(file.FullName)));
            }

           
            return foundfiles;

        }

        public ulong GetSize(string path)
        {
            var absolutepath = _userRootDirectory + path;
            
            FileInfo fi = new FileInfo(absolutepath);
            if (fi.Exists)
                return (ulong)fi.Length;
            return 0;
        }

        public bool MakeDirectory(string newPath)
        {
            var absolutepath = _userRootDirectory + newPath;
            System.IO.DirectoryInfo di = new DirectoryInfo(absolutepath);
            try
            {
                di.Create();
                return true;
            }
            catch 
            {
                return false;
            }
        }

        public Stream OpenStreamRead(string path)
        {
            var absolutepath = _userRootDirectory + path;
            System.IO.FileInfo fi = new System.IO.FileInfo(absolutepath);
            var fs = fi.OpenRead();
            return fs;
        }

        public Stream OpenStreamWrite(string path)
        {
            var newfs = new FileStream(_userRootDirectory + path, FileMode.OpenOrCreate);
            return newfs;

        }

        public bool RemoveDirectory(string pathToRemove)
        {
            var absolutepath = _userRootDirectory + pathToRemove;
            DirectoryInfo di = new DirectoryInfo(absolutepath);
            FileInfo fi = new FileInfo(absolutepath); // Renci SSH uses this command to remove a file too, so we must check if path is a dir or file

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
            var absolutepath = _userRootDirectory + pathToRemove;
            FileInfo fi = new FileInfo(absolutepath); // Renci SSH uses this command to remove a file too, so we must check if path is a dir or file

            if (fi.Exists)
            {
                fi.Delete();
                return true;
            }
            return false;
        }

        public IEnumerable<Resource> GetDirectories(string path)
        {

            var absolutepath = _userRootDirectory + path;

            DirectoryInfo diRoot = new DirectoryInfo(_userRootDirectory + "/");
            DirectoryInfo di = new DirectoryInfo(absolutepath);
            //absolutepath = di.FullName.Replace(_userRootDirectory, "/").Replace("\\", "/").Replace("//", "/");

            if (diRoot.Parent?.FullName == di.FullName || diRoot.Parent?.Parent?.FullName == di.FullName)
            {
                di = new DirectoryInfo(_userRootDirectory);
            }

            var foundDirs = new List<Resource>();

            foreach (var dir in di.GetDirectories())
            {
                foundDirs.Add(MapDirectoryToResource(new FileInfo(dir.FullName)));

            }

            if (diRoot.FullName != di.FullName && path != "/" && !string.IsNullOrWhiteSpace(path) && !path.EndsWith(".."))
            {
                var parent = MapDirectoryToResource(new FileInfo(di.Parent.FullName));  // if not on root level, add parent too
                parent.Name = "..";
                foundDirs.Add(parent);

            }

            return foundDirs;

        }

        public bool MoveFileOrDirectory(string oldpath, string newpath)
        {
            var oldpathAbsolute = _userRootDirectory + oldpath;
            var newpathAbsolute = _userRootDirectory + newpath;

            DirectoryInfo di = new DirectoryInfo(oldpathAbsolute);
            if (di.Exists)
            {
                try
                {
                    di.MoveTo(newpathAbsolute);
                    return true;
                }
                catch
                {
                    return false;
                }
            }
            else
            {
                FileInfo fi = new FileInfo(oldpathAbsolute);
                if (fi.Exists)
                {
                    try
                    {
                        fi.MoveTo(newpathAbsolute);
                        return true;
                    }
                    catch
                    {
                        return false;
                    }
                }
            }
            return false;
        }

        private Resource MapDirectoryToResource(FileInfo fileInfo)
        {
            Resource res = new Resource()
            {
                Type = ResourceType.Folder,
                FullName = fileInfo.FullName,
                Length = 0,
                Name = fileInfo.Name
            };
            return res;
        }

        private Resource MapFileToResource(FileInfo fileInfo)
        {
            Resource res = new Resource()
            {
                Type = ResourceType.File,
                FullName = fileInfo.FullName,
                Length = (ulong)fileInfo.Length,
                Name = fileInfo.Name
            };
            return res;
        }
        public DateTime GetDirectoryLastModified(string path)
        {
            //var absolutepath = _userRootDirectory + path;
            var dirInfo = new DirectoryInfo(path);
            return dirInfo.LastWriteTimeUtc;
        }
        public DateTime GetDirectoryLastAccessed(string path)
        {
            //var absolutepath = _userRootDirectory + path;
            var dirInfo = new DirectoryInfo(path);
            return dirInfo.LastAccessTimeUtc;
        }

        public DateTime GetFileLastModified(string path)
        {
            //var absolutepath = _userRootDirectory + path;
            var fileInfo = new FileInfo(path);
            return fileInfo.LastWriteTimeUtc;
        }
        public DateTime GetFileLastAccessed(string path)
        {
            //var absolutepath = _userRootDirectory + path;
            var fileInfo = new FileInfo(path);
            return fileInfo.LastAccessTimeUtc;
        }


    }
}
