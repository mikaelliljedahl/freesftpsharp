using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage;

/// <summary>
/// A file system whose handles record whether they were closed by <see cref="IFileHandle.DisposeAsync"/> or by
/// <see cref="IFileHandle.AbortAsync"/>, then do the same on the handle of <paramref name="inner"/>. The tests of a
/// decorator or of the SFTP adapter use it to prove that an abort reaches the storage as an abort.
/// </summary>
public sealed class AbortSpyFileSystem(IFileSystem inner) : IFileSystem
{
    private readonly List<string> _closes = new();

    /// <summary>"Dispose" or "Abort" for each handle that was closed, in order.</summary>
    public IReadOnlyList<string> Closes
    {
        get
        {
            lock (_closes)
                return _closes.ToList();
        }
    }

    public StorageCapabilities Capabilities => inner.Capabilities;

    public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct) => inner.StatAsync(path, followLinks, ct);

    public IAsyncEnumerable<FileSystemEntry> ListAsync(string path, CancellationToken ct) => inner.ListAsync(path, ct);

    public async ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct)
        => new Handle(this, await inner.OpenAsync(path, flags, initial, ct));

    public ValueTask CreateDirectoryAsync(string path, CancellationToken ct) => inner.CreateDirectoryAsync(path, ct);

    public ValueTask DeleteFileAsync(string path, CancellationToken ct) => inner.DeleteFileAsync(path, ct);

    public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct) => inner.DeleteDirectoryAsync(path, ct);

    public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct) => inner.RenameAsync(oldPath, newPath, flags, ct);

    public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct) => inner.SetAttributesAsync(path, update, ct);

    public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct) => inner.GetStorageSpaceAsync(path, ct);

    private void Record(string how)
    {
        lock (_closes)
            _closes.Add(how);
    }

    private sealed class Handle(AbortSpyFileSystem owner, IFileHandle inner) : IFileHandle
    {
        public ValueTask<int> ReadAsync(long offset, Memory<byte> buffer, CancellationToken ct) => inner.ReadAsync(offset, buffer, ct);

        public ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct) => inner.WriteAsync(offset, data, ct);

        public ValueTask FlushAsync(CancellationToken ct) => inner.FlushAsync(ct);

        public ValueTask<FileSystemEntry> StatAsync(CancellationToken ct) => inner.StatAsync(ct);

        public ValueTask SetAttributesAsync(FileAttributesUpdate update, CancellationToken ct) => inner.SetAttributesAsync(update, ct);

        public ValueTask DisposeAsync()
        {
            owner.Record("Dispose");
            return inner.DisposeAsync();
        }

        public ValueTask AbortAsync()
        {
            owner.Record("Abort");
            return inner.AbortAsync();
        }
    }
}
