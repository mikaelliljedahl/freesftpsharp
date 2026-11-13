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
    bool FileExists(string path);
    Stream OpenStreamRead(string path);
    Stream OpenStreamWrite(string path);
    Stream OpenStreamWrite(string path, FileMode mode);
    IEnumerable<Resource> GetFiles(string path);
    IEnumerable<Resource> GetDirectories(string path);
    bool RemoveFile(string path);
    ulong GetSize(string path);
    DateTime GetDirectoryLastModified(string path);
    DateTime GetDirectoryLastAccessed(string path);
    DateTime GetFileLastModified(string path);
    DateTime GetFileLastAccessed(string path);
    bool MoveFileOrDirectory(string oldpath, string newpath);

    /// <summary>Returns the type, size, times and permissions of a file or directory, or null if the path does not exist.</summary>
    FileSystemEntryInfo? GetInfo(string path);

    /// <summary>
    /// Opens a file with the given mode and access. Other handles can read, write and delete the file
    /// while the stream is open (SFTP clients open the same file again, for example for SETSTAT).
    /// </summary>
    Stream OpenFile(string path, FileMode mode, FileAccess access);

    /// <summary>Truncates or extends a file to <paramref name="length"/> bytes.</summary>
    void SetFileLength(string path, long length);

    /// <summary>Sets the last access and/or last write time (UTC) of a file or directory. A null time is not changed.</summary>
    void SetTimes(string path, DateTime? lastAccessUtc, DateTime? lastWriteUtc);

    /// <summary>
    /// Sets the POSIX permission bits (rwxrwxrwx, the lowest 9 bits of <paramref name="mode"/>) of a file
    /// or directory. Other bits (file type, setuid, setgid, sticky) are ignored. A platform without POSIX
    /// permissions applies what it can.
    /// </summary>
    void SetPermissions(string path, uint mode);
}

/// <param name="Type">File or directory.</param>
/// <param name="Length">The size in bytes; 0 for a directory.</param>
/// <param name="LastAccessUtc">The last access time (UTC).</param>
/// <param name="LastWriteUtc">The last write time (UTC).</param>
/// <param name="Permissions">The POSIX permission bits (rwxrwxrwx, lowest 9 bits).</param>
public sealed record FileSystemEntryInfo(ResourceType Type, ulong Length, DateTime LastAccessUtc, DateTime LastWriteUtc, uint Permissions);

public record struct Resource(string Name, string FullName, ResourceType Type, ulong Length);

public enum ResourceType
{
    File = 1,
    Folder = 2
}
