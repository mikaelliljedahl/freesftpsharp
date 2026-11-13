using SshServer.Interfaces;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Sftp;

/// <summary>A file system whose every member throws the exception that <c>create</c> gives.</summary>
internal sealed class ThrowingFileSystem(Func<Exception> create) : IFileSystem
{
    private Exception Fail() => create();

    public StorageCapabilities Capabilities => throw Fail();
    public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct) => throw Fail();
    public IAsyncEnumerable<FileSystemEntry> ListAsync(string path, CancellationToken ct) => throw Fail();
    public ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct) => throw Fail();
    public ValueTask CreateDirectoryAsync(string path, CancellationToken ct) => throw Fail();
    public ValueTask DeleteFileAsync(string path, CancellationToken ct) => throw Fail();
    public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct) => throw Fail();
    public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct) => throw Fail();
    public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct) => throw Fail();
    public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct) => throw Fail();

    public bool RemoveDirectory(string pathToRemove) => throw Fail();
    public bool MakeDirectory(string newPath) => throw Fail();
    public bool DirectoryExists(string path) => throw Fail();
    public bool FileExists(string path) => throw Fail();
    public Stream OpenStreamRead(string path) => throw Fail();
    public Stream OpenStreamWrite(string path) => throw Fail();
    public Stream OpenStreamWrite(string path, FileMode mode) => throw Fail();
    public IEnumerable<Resource> GetFiles(string path) => throw Fail();
    public IEnumerable<Resource> GetDirectories(string path) => throw Fail();
    public bool RemoveFile(string path) => throw Fail();
    public ulong GetSize(string path) => throw Fail();
    public DateTime GetDirectoryLastModified(string path) => throw Fail();
    public DateTime GetDirectoryLastAccessed(string path) => throw Fail();
    public DateTime GetFileLastModified(string path) => throw Fail();
    public DateTime GetFileLastAccessed(string path) => throw Fail();
    public bool MoveFileOrDirectory(string oldpath, string newpath) => throw Fail();
    public FileSystemEntryInfo? GetInfo(string path) => throw Fail();
    public Stream OpenFile(string path, FileMode mode, FileAccess access) => throw Fail();
    public void SetFileLength(string path, long length) => throw Fail();
    public void SetTimes(string path, DateTime? lastAccessUtc, DateTime? lastWriteUtc) => throw Fail();
    public void SetPermissions(string path, uint mode) => throw Fail();
    public void RenameReplacing(string oldPath, string newPath) => throw Fail();
    public StorageSpace? GetStorageSpace(string path) => throw Fail();
}
