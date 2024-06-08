using System.Collections.Generic;
using System.IO;

namespace SshServerModule.Services
{
    public interface IFileSystem
    {
        void RemoveDirectory(string pathToRemove);
        void MakeDirectory(string newPath);
        bool DirectoryExists(string path);
        Stream OpenStreamRead(string path);
        Stream OpenStreamWrite(string path);
        IEnumerable<Resource> GetFiles(string path);
        IEnumerable<Resource> GetDirectories();
        void RemoveFile(string path);
        ulong GetSize(string path);
    }

    public record struct Resource(string Name, string FullName, ResourceType Type, ulong Length);

    public enum ResourceType
    {
        File = 1,
        Folder = 2
    }
}
