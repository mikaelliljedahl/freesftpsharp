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
}
