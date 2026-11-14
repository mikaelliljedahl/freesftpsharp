using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage;

/// <summary>
/// An <see cref="IFileSystem"/> that records every operation that reaches it and then forwards it to
/// <paramref name="inner"/>. The tests of a decorator use it to prove that a refused operation never reaches the backend.
/// </summary>
public sealed class RecordingFileSystem(IFileSystem inner) : IFileSystem
{
    private readonly List<string> _calls = new();

    /// <summary>The names of the operations that reached this file system, in order.</summary>
    public IReadOnlyList<string> Calls
    {
        get
        {
            lock (_calls)
                return _calls.ToList();
        }
    }

    private void Record(string operation)
    {
        lock (_calls)
            _calls.Add(operation);
    }

    public StorageCapabilities Capabilities => inner.Capabilities;

    public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct)
    {
        Record(nameof(StatAsync));
        return inner.StatAsync(path, followLinks, ct);
    }

    public IAsyncEnumerable<FileSystemEntry> ListAsync(string path, CancellationToken ct)
    {
        Record(nameof(ListAsync));
        return inner.ListAsync(path, ct);
    }

    public ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct)
    {
        Record(nameof(OpenAsync));
        return inner.OpenAsync(path, flags, initial, ct);
    }

    public ValueTask CreateDirectoryAsync(string path, CancellationToken ct)
    {
        Record(nameof(CreateDirectoryAsync));
        return inner.CreateDirectoryAsync(path, ct);
    }

    public ValueTask DeleteFileAsync(string path, CancellationToken ct)
    {
        Record(nameof(DeleteFileAsync));
        return inner.DeleteFileAsync(path, ct);
    }

    public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct)
    {
        Record(nameof(DeleteDirectoryAsync));
        return inner.DeleteDirectoryAsync(path, ct);
    }

    public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct)
    {
        Record(nameof(RenameAsync));
        return inner.RenameAsync(oldPath, newPath, flags, ct);
    }

    public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct)
    {
        Record(nameof(SetAttributesAsync));
        return inner.SetAttributesAsync(path, update, ct);
    }

    public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct)
    {
        Record(nameof(GetStorageSpaceAsync));
        return inner.GetStorageSpaceAsync(path, ct);
    }
}
