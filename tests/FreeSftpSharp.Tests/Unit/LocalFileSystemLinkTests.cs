using FreeSftpSharp.Tests.Infrastructure;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>
/// A symbolic link or junction inside the user root never gives access outside the root (issue #25).
/// The temporary directory has the user root <c>root</c> and a directory <c>outside</c> next to it with a
/// secret file.
/// </summary>
public sealed class LocalFileSystemLinkTests : IDisposable
{
    private const string Secret = "secret";

    private readonly string _tempDirectory;
    private readonly string _root;
    private readonly string _outside;
    private readonly string _secretFile;
    private readonly LocalFileSystem _fileSystem;

    public LocalFileSystemLinkTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), "freesftpsharp-tests", Guid.NewGuid().ToString("N"));
        _root = Path.Combine(_tempDirectory, "root");
        _outside = Path.Combine(_tempDirectory, "outside");
        Directory.CreateDirectory(_root);
        Directory.CreateDirectory(_outside);
        _secretFile = Path.Combine(_outside, "secret.txt");
        File.WriteAllText(_secretFile, Secret);
        _fileSystem = new LocalFileSystem(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDirectory, recursive: true); } catch { }
    }

    private const FileOpenFlags WriteNew = FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private async Task<bool> ExistsAsync(string path, FileSystemEntryType type)
        => (await _fileSystem.StatAsync(path, true, Ct))?.Type == type;

    private Task<bool> FileExistsAsync(string path) => ExistsAsync(path, FileSystemEntryType.File);

    private Task<bool> DirectoryExistsAsync(string path) => ExistsAsync(path, FileSystemEntryType.Directory);

    private async Task<List<FileSystemEntry>> ListAsync(string path)
    {
        var entries = new List<FileSystemEntry>();
        await foreach (var entry in _fileSystem.ListAsync(path, Ct))
            entries.Add(entry);
        return entries;
    }

    private async Task OpenAndCloseAsync(string path, FileOpenFlags flags)
        => await (await _fileSystem.OpenAsync(path, flags, null, Ct)).DisposeAsync();

    /// <summary>The operation is refused: PermissionDenied (a path that leads outside the root).</summary>
    private static async Task AssertDeniedAsync(Func<Task> action)
    {
        var ex = await Assert.ThrowsAsync<FileSystemException>(action);
        Assert.Equal(FileSystemError.PermissionDenied, ex.Error);
    }

    private static void AssertDenied(Action action)
    {
        var ex = Assert.Throws<FileSystemException>(action);
        Assert.Equal(FileSystemError.PermissionDenied, ex.Error);
    }

    private string InRoot(string relative) => Path.Combine(_root, relative.Replace('/', Path.DirectorySeparatorChar));

    [Fact]
    public async Task Link_to_a_directory_outside_the_root_is_refused_for_every_operation()
    {
        FileLinks.CreateDirectoryLink(InRoot("out"), _outside);

        AssertDenied(() => _fileSystem.GetPhysicalPath("/out"));
        AssertDenied(() => _fileSystem.GetPhysicalPath("/out/secret.txt"));
        await AssertDeniedAsync(() => DirectoryExistsAsync("/out"));
        await AssertDeniedAsync(() => FileExistsAsync("/out/secret.txt"));
        await AssertDeniedAsync(() => ListAsync("/out"));
        await AssertDeniedAsync(() => OpenAndCloseAsync("/out/secret.txt", FileOpenFlags.Read));
        await AssertDeniedAsync(() => OpenAndCloseAsync("/out/new.txt", WriteNew));
        await AssertDeniedAsync(() => OpenAndCloseAsync("/out/secret.txt", WriteNew));
        await AssertDeniedAsync(() => _fileSystem.DeleteFileAsync("/out/secret.txt", Ct).AsTask());
        await AssertDeniedAsync(() => _fileSystem.DeleteDirectoryAsync("/out", Ct).AsTask());
        await AssertDeniedAsync(() => _fileSystem.SetAttributesAsync("/out/secret.txt", new FileAttributesUpdate { Size = 0 }, Ct).AsTask());
        await AssertDeniedAsync(() => _fileSystem.SetAttributesAsync("/out/secret.txt", new FileAttributesUpdate { Permissions = 0x1FF }, Ct).AsTask());
        await AssertDeniedAsync(() => _fileSystem.SetAttributesAsync("/out/secret.txt",
            new FileAttributesUpdate { LastAccessTimeUtc = DateTime.UnixEpoch, LastWriteTimeUtc = DateTime.UnixEpoch }, Ct).AsTask());
        await AssertDeniedAsync(() => _fileSystem.GetStorageSpaceAsync("/out", Ct).AsTask());
        await AssertDeniedAsync(() => _fileSystem.CreateDirectoryAsync("/out/newdir", Ct).AsTask());
        await AssertDeniedAsync(() => _fileSystem.RenameAsync("/out/secret.txt", "/stolen.txt", RenameFlags.None, Ct).AsTask());
        await AssertDeniedAsync(() => _fileSystem.RenameAsync("/out/secret.txt", "/stolen.txt", RenameFlags.ReplaceExisting, Ct).AsTask());
        File.WriteAllText(InRoot("mine.txt"), "mine");
        await AssertDeniedAsync(() => _fileSystem.RenameAsync("/mine.txt", "/out/mine.txt", RenameFlags.None, Ct).AsTask());

        Assert.Equal(Secret, File.ReadAllText(_secretFile));
        Assert.Equal(["secret.txt"], Directory.GetFileSystemEntries(_outside).Select(Path.GetFileName));
        Assert.False(File.Exists(InRoot("stolen.txt")));
    }

    [Fact]
    public async Task Relative_link_that_leaves_the_root_is_refused()
    {
        FileLinks.CreateDirectoryLink(InRoot("up"), Path.Combine("..", "outside"));

        await AssertDeniedAsync(() => FileExistsAsync("/up/secret.txt"));
    }

    [Fact]
    public async Task Link_in_a_subdirectory_to_the_parent_of_the_root_is_refused()
    {
        Directory.CreateDirectory(InRoot("a/b"));
        FileLinks.CreateDirectoryLink(InRoot("a/b/top"), Path.Combine("..", "..", ".."));

        await AssertDeniedAsync(() => FileExistsAsync("/a/b/top/outside/secret.txt"));
        await AssertDeniedAsync(() => ListAsync("/a/b/top"));
    }

    [Fact]
    public async Task Chain_of_links_that_ends_outside_the_root_is_refused()
    {
        FileLinks.CreateDirectoryLink(InRoot("second"), _outside);
        FileLinks.CreateDirectoryLink(InRoot("first"), InRoot("second"));

        await AssertDeniedAsync(() => FileExistsAsync("/first/secret.txt"));
    }

    [Fact]
    public async Task Link_to_a_file_outside_the_root_is_refused()
    {
        FileLinks.CreateFileLink(InRoot("secret-link.txt"), _secretFile);

        await AssertDeniedAsync(() => FileExistsAsync("/secret-link.txt"));
        await AssertDeniedAsync(() => OpenAndCloseAsync("/secret-link.txt", FileOpenFlags.Read));
        await AssertDeniedAsync(() => OpenAndCloseAsync("/secret-link.txt", FileOpenFlags.Write));
        Assert.Equal(Secret, File.ReadAllText(_secretFile));
    }

    [Fact]
    public async Task Dangling_link_to_a_missing_file_outside_the_root_cannot_create_it()
    {
        var target = Path.Combine(_outside, "created.txt");
        FileLinks.CreateFileLink(InRoot("dangling.txt"), target);

        await AssertDeniedAsync(() => OpenAndCloseAsync("/dangling.txt", FileOpenFlags.Write | FileOpenFlags.Create));
        Assert.False(File.Exists(target));
    }

    [Fact]
    public async Task Link_to_a_directory_inside_the_root_keeps_working()
    {
        Directory.CreateDirectory(InRoot("real"));
        File.WriteAllText(InRoot("real/file.txt"), "inside");
        FileLinks.CreateDirectoryLink(InRoot("alias"), InRoot("real"));
        FileLinks.CreateDirectoryLink(InRoot("relative-alias"), "real");

        Assert.True(await DirectoryExistsAsync("/alias"));
        Assert.True(await FileExistsAsync("/alias/file.txt"));
        Assert.True(await FileExistsAsync("/relative-alias/file.txt"));
        Assert.Contains(await ListAsync("/alias"), f => f.Name == "file.txt");
        Assert.Contains(await ListAsync("/"), f => f.Name == "alias" && f.IsDirectory);
        await using (var handle = await _fileSystem.OpenAsync("/alias/new.txt", WriteNew, null, Ct))
            await handle.WriteAsync(0, new byte[] { 1 }, Ct);
        Assert.True(File.Exists(InRoot("real/new.txt")));
        await _fileSystem.CreateDirectoryAsync("/alias/sub", Ct);
        Assert.True(Directory.Exists(InRoot("real/sub")));
    }

    [Fact]
    public async Task Link_to_a_file_inside_the_root_keeps_working()
    {
        File.WriteAllText(InRoot("file.txt"), "inside");
        FileLinks.CreateFileLink(InRoot("file-link.txt"), "file.txt");

        await using var handle = await _fileSystem.OpenAsync("/file-link.txt", FileOpenFlags.Read, null, Ct);
        var buffer = new byte[100];
        var read = await handle.ReadAsync(0, buffer, Ct);
        Assert.Equal("inside", System.Text.Encoding.UTF8.GetString(buffer, 0, read));
    }

    [Fact]
    public async Task Link_that_goes_out_and_comes_back_inside_the_root_keeps_working()
    {
        Directory.CreateDirectory(InRoot("real"));
        File.WriteAllText(InRoot("real/file.txt"), "inside");
        FileLinks.CreateDirectoryLink(InRoot("roundtrip"), Path.Combine("..", "root", "real"));

        Assert.True(await FileExistsAsync("/roundtrip/file.txt"));
    }

    [Fact]
    public async Task Root_reached_through_a_link_to_its_parent_cannot_be_removed_moved_or_changed()
    {
        FileLinks.CreateDirectoryLink(InRoot("parent"), _tempDirectory);

        await AssertDeniedAsync(() => _fileSystem.DeleteDirectoryAsync("/parent/root", Ct).AsTask());
        await AssertDeniedAsync(() => _fileSystem.RenameAsync("/parent/root", "/moved", RenameFlags.None, Ct).AsTask());
        await AssertDeniedAsync(() => _fileSystem.RenameAsync("/a.txt", "/parent/root", RenameFlags.ReplaceExisting, Ct).AsTask());
        await AssertDeniedAsync(() => _fileSystem.SetAttributesAsync("/parent/root", new FileAttributesUpdate { Permissions = 0 }, Ct).AsTask());
        Assert.True(Directory.Exists(_root));
        Assert.True(Directory.Exists(InRoot("parent")));
    }

    [Fact]
    public async Task Link_to_the_root_can_be_removed_and_the_root_stays()
    {
        FileLinks.CreateDirectoryLink(InRoot("self"), _root);

        await _fileSystem.DeleteDirectoryAsync("/self", Ct);

        Assert.False(Path.Exists(InRoot("self")));
        Assert.True(Directory.Exists(_root));
    }

    [Fact]
    public async Task Root_that_is_a_link_keeps_working()
    {
        var linkedRoot = Path.Combine(_tempDirectory, "root-link");
        FileLinks.CreateDirectoryLink(linkedRoot, _root);
        File.WriteAllText(InRoot("file.txt"), "inside");
        var fileSystem = new LocalFileSystem(linkedRoot);

        Assert.Equal(FileSystemEntryType.File, (await fileSystem.StatAsync("/file.txt", true, Ct))?.Type);
        Assert.Equal(FileSystemEntryType.Directory, (await fileSystem.StatAsync("/", true, Ct))?.Type);
    }

    [Fact]
    public async Task Path_below_a_file_or_a_missing_directory_is_not_found_and_not_refused()
    {
        File.WriteAllText(InRoot("file.txt"), "x");

        Assert.Null(await _fileSystem.StatAsync("/file.txt/child", true, Ct));
        Assert.Null(await _fileSystem.StatAsync("/missing/child", true, Ct));
    }

    [Fact]
    public async Task Link_loop_gives_an_error_and_no_hang()
    {
        if (OperatingSystem.IsWindows())
            Assert.Skip("A link loop is a POSIX test; junctions to a missing target cannot be created.");
        Directory.CreateSymbolicLink(InRoot("loop-a"), "loop-b");
        Directory.CreateSymbolicLink(InRoot("loop-b"), "loop-a");

        var ex = await Record.ExceptionAsync(() => FileExistsAsync("/loop-a/x"));

        Assert.IsType<FileSystemException>(ex);
    }
}
