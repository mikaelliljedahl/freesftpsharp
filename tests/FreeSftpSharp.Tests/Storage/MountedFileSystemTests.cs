using System.Text;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Storage;

/// <summary>
/// <see cref="MountedFileSystem"/> (issue #56): routing to the storage with the longest mount path, mount points in
/// listings, virtual parents, and the operations that cross or touch a mount point.
/// </summary>
public sealed class MountedFileSystemTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly InMemoryFileSystem _root = new();
    private readonly InMemoryFileSystem _shared = new();
    private readonly InMemoryFileSystem _archive = new(StorageCapabilities.Rename);

    private MountedFileSystem Create(params (string Path, IFileSystem FileSystem)[] mounts)
        => new(_root, mounts.Select(m => new MountedFileSystem.Mount(m.Path, m.FileSystem)));

    private MountedFileSystem Default() => Create(("/shared", _shared), ("/deep/archive", _archive));

    private static async Task WriteAsync(IFileSystem fs, string path, string content)
    {
        await using var handle = await fs.OpenAsync(path, FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate, null, Ct);
        await handle.WriteAsync(0, Encoding.UTF8.GetBytes(content), Ct);
    }

    private static async Task<string> ReadAsync(IFileSystem fs, string path)
    {
        await using var handle = await fs.OpenAsync(path, FileOpenFlags.Read, null, Ct);
        var buffer = new byte[4096];
        var read = await handle.ReadAsync(0, buffer, Ct);
        return Encoding.UTF8.GetString(buffer, 0, read);
    }

    private static async Task<List<string>> NamesAsync(IFileSystem fs, string path)
    {
        var names = new List<string>();
        await foreach (var entry in fs.ListAsync(path, Ct))
            names.Add(entry.Name);
        names.Sort(StringComparer.Ordinal);
        return names;
    }

    private static async Task<FileSystemError> ErrorAsync(Func<Task> action)
        => (await Assert.ThrowsAsync<FileSystemException>(action)).Error;

    [Fact]
    public async Task A_path_below_a_mount_goes_to_the_mounted_storage_with_the_path_inside_it()
    {
        var fs = Default();

        await WriteAsync(fs, "/shared/a.txt", "shared");
        await WriteAsync(fs, "/a.txt", "root");
        await fs.CreateDirectoryAsync("/deep/archive/2026", Ct);

        Assert.Equal("shared", await ReadAsync(_shared, "/a.txt"));
        Assert.Equal("root", await ReadAsync(_root, "/a.txt"));
        Assert.True((await _archive.StatAsync("/2026", true, Ct))!.IsDirectory);
        Assert.Null(await _root.StatAsync("/shared", true, Ct));
        Assert.Equal("shared", await ReadAsync(fs, "/shared/a.txt"));
    }

    [Fact]
    public async Task The_longest_mount_path_wins_for_nested_mounts()
    {
        var inner = new InMemoryFileSystem();
        var fs = Create(("/shared", _shared), ("/shared/inner", inner));

        await WriteAsync(fs, "/shared/inner/x.txt", "inner");
        await WriteAsync(fs, "/shared/y.txt", "shared");

        Assert.Equal("inner", await ReadAsync(inner, "/x.txt"));
        Assert.Equal("shared", await ReadAsync(_shared, "/y.txt"));
        Assert.Equal(["inner", "y.txt"], await NamesAsync(fs, "/shared"));
    }

    [Fact]
    public async Task A_mount_path_is_matched_by_whole_segments_only()
    {
        var fs = Default();

        await WriteAsync(fs, "/sharedfile.txt", "root");

        Assert.Equal("root", await ReadAsync(_root, "/sharedfile.txt"));
        Assert.Null(await _shared.StatAsync("/file.txt", true, Ct));
    }

    [Fact]
    public async Task The_root_listing_shows_mount_points_and_virtual_parents_as_directories()
    {
        await _root.CreateDirectoryAsync("/home", Ct);
        await WriteAsync(_root, "/shared", "a file hidden by the mount");
        var fs = Default();

        Assert.Equal(["deep", "home", "shared"], await NamesAsync(fs, "/"));
        await foreach (var entry in fs.ListAsync("/", Ct))
            Assert.True(entry.IsDirectory, entry.Name);
        Assert.Equal(["archive"], await NamesAsync(fs, "/deep"));
        Assert.Empty(await NamesAsync(fs, "/deep/archive"));
    }

    [Fact]
    public async Task A_mount_point_has_the_attributes_of_the_mounted_root_with_its_own_name()
    {
        var fs = Default();

        var mount = await fs.StatAsync("/shared", true, Ct);
        var parent = await fs.StatAsync("/deep", true, Ct);

        Assert.NotNull(mount);
        Assert.Equal("shared", mount.Name);
        Assert.True(mount.IsDirectory);
        Assert.Equal("deep", parent!.Name);
        Assert.True(parent.IsDirectory);
    }

    [Fact]
    public async Task A_real_directory_that_holds_a_mount_lists_its_own_entries_and_the_mount()
    {
        await _root.CreateDirectoryAsync("/deep", Ct);
        await WriteAsync(_root, "/deep/readme.txt", "x");
        var fs = Default();

        Assert.Equal(["archive", "readme.txt"], await NamesAsync(fs, "/deep"));
    }

    [Fact]
    public async Task A_mount_point_cannot_be_removed_renamed_or_replaced()
    {
        await _root.CreateDirectoryAsync("/dir", Ct);
        await WriteAsync(_root, "/file.txt", "x");
        var fs = Default();

        Assert.Equal(FileSystemError.PermissionDenied, await ErrorAsync(() => fs.DeleteDirectoryAsync("/shared", Ct).AsTask()));
        Assert.Equal(FileSystemError.DirectoryNotEmpty, await ErrorAsync(() => fs.DeleteDirectoryAsync("/deep", Ct).AsTask()));
        Assert.Equal(FileSystemError.IsADirectory, await ErrorAsync(() => fs.DeleteFileAsync("/shared", Ct).AsTask()));
        Assert.Equal(FileSystemError.PermissionDenied, await ErrorAsync(() => fs.RenameAsync("/shared", "/other", RenameFlags.None, Ct).AsTask()));
        Assert.Equal(FileSystemError.PermissionDenied, await ErrorAsync(() => fs.RenameAsync("/deep", "/other", RenameFlags.None, Ct).AsTask()));
        Assert.Equal(FileSystemError.PermissionDenied, await ErrorAsync(() => fs.RenameAsync("/dir", "/shared", RenameFlags.None, Ct).AsTask()));
        Assert.Equal(FileSystemError.AlreadyExists, await ErrorAsync(() => fs.RenameAsync("/dir", "/deep", RenameFlags.None, Ct).AsTask()));
        Assert.Equal(FileSystemError.IsADirectory, await ErrorAsync(() => fs.RenameAsync("/file.txt", "/deep", RenameFlags.ReplaceExisting, Ct).AsTask()));
        Assert.Equal(FileSystemError.AlreadyExists, await ErrorAsync(() => fs.CreateDirectoryAsync("/shared", Ct).AsTask()));
        Assert.Equal(FileSystemError.AlreadyExists, await ErrorAsync(() => fs.CreateDirectoryAsync("/deep", Ct).AsTask()));
        Assert.Equal(FileSystemError.IsADirectory, await ErrorAsync(() =>
            fs.OpenAsync("/deep", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct).AsTask()));
        Assert.Equal(FileSystemError.PermissionDenied, await ErrorAsync(() =>
            fs.SetAttributesAsync("/deep", new FileAttributesUpdate { Permissions = 0x1FF }, Ct).AsTask()));
        await fs.SetAttributesAsync("/deep", new FileAttributesUpdate(), Ct); // an empty SETSTAT is fine
        Assert.Equal(["deep", "dir", "file.txt", "shared"], await NamesAsync(fs, "/"));
    }

    [Fact]
    public async Task A_rename_across_mounts_is_not_supported_and_changes_nothing()
    {
        var fs = Default();
        await WriteAsync(fs, "/a.txt", "root");
        await WriteAsync(fs, "/shared/b.txt", "shared");

        Assert.Equal(FileSystemError.OpNotSupported, await ErrorAsync(() => fs.RenameAsync("/a.txt", "/shared/a.txt", RenameFlags.None, Ct).AsTask()));
        Assert.Equal(FileSystemError.OpNotSupported, await ErrorAsync(() => fs.RenameAsync("/shared/b.txt", "/b.txt", RenameFlags.None, Ct).AsTask()));
        Assert.Equal(FileSystemError.OpNotSupported, await ErrorAsync(() =>
            fs.RenameAsync("/shared/b.txt", "/deep/archive/b.txt", RenameFlags.ReplaceExisting, Ct).AsTask()));

        Assert.Equal("root", await ReadAsync(_root, "/a.txt"));
        Assert.Equal("shared", await ReadAsync(_shared, "/b.txt"));
        Assert.Null(await _shared.StatAsync("/a.txt", true, Ct));
        Assert.Null(await _archive.StatAsync("/b.txt", true, Ct));
    }

    [Fact]
    public async Task A_rename_inside_one_mount_uses_that_storage()
    {
        var fs = Default();
        await WriteAsync(fs, "/shared/a.txt", "x");
        await fs.CreateDirectoryAsync("/shared/dir", Ct);

        await fs.RenameAsync("/shared/a.txt", "/shared/dir/b.txt", RenameFlags.None, Ct);

        Assert.Equal("x", await ReadAsync(_shared, "/dir/b.txt"));
        Assert.Null(await _shared.StatAsync("/a.txt", true, Ct));
    }

    [Fact]
    public async Task A_rename_inside_a_mount_without_the_rename_capability_gives_its_error()
    {
        var noRename = new InMemoryFileSystem(StorageCapabilities.None);
        var fs = Create(("/ro", noRename));
        await WriteAsync(fs, "/ro/a.txt", "x");

        Assert.Equal(FileSystemError.OpNotSupported, await ErrorAsync(() => fs.RenameAsync("/ro/a.txt", "/ro/b.txt", RenameFlags.None, Ct).AsTask()));
    }

    [Fact]
    public async Task Capabilities_are_what_every_storage_can_do()
    {
        var fs = Default();

        Assert.Equal(StorageCapabilities.Rename, fs.Capabilities);
        Assert.Equal(InMemoryFileSystem.AllCapabilities, Create(("/shared", _shared)).Capabilities);
    }

    [Fact]
    public async Task Case_insensitive_paths_of_one_storage_make_the_whole_file_system_case_insensitive()
    {
        var fs = Create(("/ci", new CaseInsensitiveFileSystem(new InMemoryFileSystem())));

        Assert.True((fs.Capabilities & StorageCapabilities.CaseInsensitivePaths) != 0);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task On_a_case_insensitive_root_the_mount_path_matches_every_spelling()
    {
        var root = new CaseInsensitiveFileSystem(new InMemoryFileSystem());
        var fs = new MountedFileSystem(root, [new MountedFileSystem.Mount("/Shared", _shared)]);

        await WriteAsync(fs, "/SHARED/a.txt", "x");

        Assert.Equal("x", await ReadAsync(_shared, "/a.txt"));
    }

    [Fact]
    public async Task A_listing_of_the_parent_still_works_when_a_mounted_storage_fails()
    {
        var fs = Create(("/broken", new BrokenFileSystem()));

        Assert.Equal(["broken"], await NamesAsync(fs, "/"));
        Assert.Equal(FileSystemError.Failure, await ErrorAsync(async () => await NamesAsync(fs, "/broken")));
    }

    [Fact]
    public async Task Paths_are_normalized_before_routing()
    {
        var fs = Default();

        await WriteAsync(fs, "/home/../shared/./a.txt", "x");
        await WriteAsync(fs, "\\shared\\b.txt", "y");

        Assert.Equal("x", await ReadAsync(_shared, "/a.txt"));
        Assert.Equal("y", await ReadAsync(_shared, "/b.txt"));
    }

    [Fact]
    public async Task Storage_space_comes_from_the_storage_of_the_path()
    {
        var fs = Default();

        Assert.Equal(await _shared.GetStorageSpaceAsync("/", Ct), await fs.GetStorageSpaceAsync("/shared", Ct));
        Assert.Null(await fs.GetStorageSpaceAsync("/deep", Ct));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("")]
    [InlineData("/..")]
    public void A_mount_at_the_root_is_refused(string path)
    {
        Assert.Throws<ArgumentException>(() => Create((path, _shared)));
    }

    [Fact]
    public void Two_mounts_at_the_same_path_are_refused()
    {
        Assert.Throws<ArgumentException>(() => Create(("/a", _shared), ("/a/", _archive)));
    }

    /// <summary>A storage that cannot be reached: every operation fails.</summary>
    private sealed class BrokenFileSystem : IFileSystem
    {
        private static FileSystemException Fail() => new(FileSystemError.Failure, "The storage cannot be reached.");
        public StorageCapabilities Capabilities => StorageCapabilities.None;
        public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct) => throw Fail();
        public async IAsyncEnumerable<FileSystemEntry> ListAsync(string path, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
        {
            await Task.Yield();
            throw Fail();
#pragma warning disable CS0162 // an iterator needs a yield
            yield break;
#pragma warning restore CS0162
        }
        public ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct) => throw Fail();
        public ValueTask CreateDirectoryAsync(string path, CancellationToken ct) => throw Fail();
        public ValueTask DeleteFileAsync(string path, CancellationToken ct) => throw Fail();
        public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct) => throw Fail();
        public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct) => throw Fail();
        public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct) => throw Fail();
        public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct) => throw Fail();
    }

    /// <summary>An <see cref="IFileSystem"/> that reports <see cref="StorageCapabilities.CaseInsensitivePaths"/> and lower-cases every path.</summary>
    private sealed class CaseInsensitiveFileSystem(IFileSystem inner) : IFileSystem
    {
        public StorageCapabilities Capabilities => inner.Capabilities | StorageCapabilities.CaseInsensitivePaths;
        private static string P(string path) => path.ToLowerInvariant();
        public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct) => inner.StatAsync(P(path), followLinks, ct);
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
