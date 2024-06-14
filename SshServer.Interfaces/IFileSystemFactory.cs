using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SshServer.Interfaces;
public interface IFileSystemFactory
{
    public IFileSystem GetFileSystem(string username);
}