using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SshServer.Interfaces;

public interface IFileSystem
{
    bool RemoveDirectory(string pathToRemove);
    bool MakeDirectory(string newPath);
    bool DirectoryExists(string path);
    Stream OpenStreamRead(string path);
    Stream OpenStreamWrite(string path);
    IEnumerable<Resource> GetFiles(string path);
    IEnumerable<Resource> GetDirectories(string path);
    bool RemoveFile(string path);
    ulong GetSize(string path);
    DateTime GetDirectoryLastModified(string path);
    DateTime GetDirectoryLastAccessed(string path);
    DateTime GetFileLastModified(string path);
    DateTime GetFileLastAccessed(string path);
}

public record struct Resource(string Name, string FullName, ResourceType Type, ulong Length);

public enum ResourceType
{
    File = 1,
    Folder = 2
}
