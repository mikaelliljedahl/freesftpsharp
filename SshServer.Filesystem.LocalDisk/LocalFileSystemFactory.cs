using SshServer.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SshServer.Filesystem.LocalDisk
{
    public class LocalFileSystemFactory : IFileSystemFactory
    {
        private readonly string _username;


        public IFileSystem GetFileSystem(string username)
        {
            throw new NotImplementedException();
            _userRootDirectory = homeDirectory;
            _username = username;
        }
    }
}
