using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Storage;

/// <summary>
/// The conformance suite inside a virtual folder: the suite works on "/mnt" of a <see cref="MountedFileSystem"/> whose
/// root and folder are different storages, so every operation goes through the routing of the mount (and the mount
/// point is the root of the suite: it cannot be removed, renamed or have its permissions changed).
/// </summary>
public sealed class MountedFileSystemConformanceTests : FileSystemConformanceTests<MountedFileSystemConformanceTests.Fixture>
{
    public sealed class Fixture : IFileSystemFixture
    {
        public IFileSystem FileSystem { get; } = new SubdirectoryView(
            new MountedFileSystem(new InMemoryFileSystem(), [new MountedFileSystem.Mount("/mnt", new InMemoryFileSystem())]), "/mnt");

        public StorageCapabilities ExpectedCapabilities => InMemoryFileSystem.AllCapabilities;
        public void Dispose() { }
    }

    /// <summary>Shows the directory <c>prefix</c> of a file system as "/" (only for this suite).</summary>
    private sealed class SubdirectoryView(IFileSystem inner, string prefix) : IFileSystem
    {
        private string P(string path) => VirtualPath.Normalize(path) is var n && n == VirtualPath.Root ? prefix : prefix + n;

        private static FileSystemEntry? Rooted(string path, FileSystemEntry? entry)
            => entry != null && VirtualPath.Normalize(path) == VirtualPath.Root ? entry with { Name = VirtualPath.Root } : entry;

        public StorageCapabilities Capabilities => inner.Capabilities;
        public async ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct) => Rooted(path, await inner.StatAsync(P(path), followLinks, ct));
        public IAsyncEnumerable<FileSystemEntry> ListAsync(string path, CancellationToken ct) => inner.ListAsync(P(path), ct);
        public ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct) => inner.OpenAsync(P(path), flags, initial, ct);
        public ValueTask CreateDirectoryAsync(string path, CancellationToken ct) => inner.CreateDirectoryAsync(P(path), ct);
        public ValueTask DeleteFileAsync(string path, CancellationToken ct) => inner.DeleteFileAsync(P(path), ct);
        public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct) => inner.DeleteDirectoryAsync(P(path), ct);
        public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct) => inner.RenameAsync(P(oldPath), P(newPath), flags, ct);
        public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct) => inner.SetAttributesAsync(P(path), update, ct);
        public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct) => inner.GetStorageSpaceAsync(P(path), ct);
    }
}
