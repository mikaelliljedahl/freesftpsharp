using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Unit;

public sealed class LocalFileSystemTests : IDisposable
{
    private readonly string _tempDirectory;
    private readonly string _root;
    private readonly LocalFileSystem _fileSystem;

    public LocalFileSystemTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), "freesftpsharp-tests", Guid.NewGuid().ToString("N"));
        _root = Path.Combine(_tempDirectory, "root");
        Directory.CreateDirectory(_root);
        _fileSystem = new LocalFileSystem(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDirectory, recursive: true); } catch { }
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("/../../etc/passwd", "/etc/passwd")]
    [InlineData("..\\..\\config.db", "/config.db")]
    [InlineData("../config.db", "/config.db")]
    [InlineData("/a/b/../../../../c", "/c")]
    [InlineData("//double//slash", "/double/slash")]
    [InlineData("/.../x", "/.../x")] // "..." is an ordinary name, not a parent reference
    [InlineData("", "/")]
    [InlineData(".", "/")]
    [InlineData("..", "/")]
    [InlineData("/", "/")]
    [InlineData("a/./b/", "/a/b")]
    [InlineData("/a\\b/c", "/a/b/c")]
    [InlineData("/a/b/..", "/a")]
    public void VirtualPath_Normalize_returns_a_rooted_path_without_dot_segments(string input, string expected)
    {
        Assert.Equal(expected, VirtualPath.Normalize(input));
    }

    [Fact]
    public void VirtualPath_Normalize_of_null_is_root()
    {
        Assert.Equal("/", VirtualPath.Normalize(null));
    }

    [Theory]
    [InlineData("/../../etc/passwd", "etc/passwd")]
    [InlineData("..\\..\\config.db", "config.db")]
    [InlineData("/../config.db", "config.db")]
    [InlineData("/a/b/../../../../c", "c")]
    [InlineData("//double//slash", "double/slash")]
    public void GetPhysicalPath_keeps_traversal_inputs_inside_the_root(string input, string expectedRelative)
    {
        var expected = Path.Combine(_root, expectedRelative.Replace('/', Path.DirectorySeparatorChar));

        Assert.Equal(expected, _fileSystem.GetPhysicalPath(input));
    }

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("/")]
    [InlineData("..")]
    [InlineData("/..")]
    [InlineData("/../..")]
    [InlineData("\\..\\..")]
    public void GetPhysicalPath_of_root_like_inputs_is_the_root(string input)
    {
        Assert.Equal(_root, _fileSystem.GetPhysicalPath(input));
    }

    [Fact]
    public void GetPhysicalPath_of_three_dots_segment_stays_inside_the_root()
    {
        // On Windows the OS can remove trailing dots, so only check that the result is inside the root.
        var physical = _fileSystem.GetPhysicalPath("/.../x");

        Assert.StartsWith(_root + Path.DirectorySeparatorChar, physical);
        if (!OperatingSystem.IsWindows())
            Assert.Equal(Path.Combine(_root, "...", "x"), physical);
    }

    [Fact]
    public async Task GetPhysicalPath_cannot_reach_a_sibling_directory_with_the_same_prefix()
    {
        var sibling = _root + "-sibling"; // for example /tmp/x/root-sibling next to /tmp/x/root
        Directory.CreateDirectory(sibling);
        File.WriteAllText(Path.Combine(sibling, "secret.txt"), "secret");

        var physical = _fileSystem.GetPhysicalPath("/../root-sibling/secret.txt");

        Assert.Equal(Path.Combine(_root, "root-sibling", "secret.txt"), physical);
        Assert.Null(await _fileSystem.StatAsync("/../root-sibling/secret.txt", true, Ct));
    }

    [Fact]
    public void Root_with_a_trailing_separator_gives_the_same_paths()
    {
        var withSeparator = new LocalFileSystem(_root + Path.DirectorySeparatorChar);

        Assert.Equal(_root, withSeparator.GetPhysicalPath("/"));
        Assert.Equal(Path.Combine(_root, "a"), withSeparator.GetPhysicalPath("/../a"));
    }

    [Fact]
    public async Task File_outside_the_root_is_not_visible()
    {
        File.WriteAllText(Path.Combine(_tempDirectory, "config.db"), "secret");

        Assert.Null(await _fileSystem.StatAsync("/../config.db", true, Ct));
        Assert.Null(await _fileSystem.StatAsync("..\\config.db", true, Ct));
        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await _fileSystem.OpenAsync("/../config.db", FileOpenFlags.Read, null, Ct));
        Assert.Equal(FileSystemError.NoSuchFile, ex.Error);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("")]
    [InlineData("/..")]
    [InlineData("/../..")]
    public async Task DeleteDirectory_never_removes_the_root(string path)
    {
        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await _fileSystem.DeleteDirectoryAsync(path, Ct));

        Assert.Equal(FileSystemError.PermissionDenied, ex.Error);
        Assert.True(Directory.Exists(_root));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/..")]
    public async Task Rename_never_moves_the_root(string path)
    {
        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await _fileSystem.RenameAsync(path, "/moved", RenameFlags.None, Ct));

        Assert.Equal(FileSystemError.PermissionDenied, ex.Error);
        Assert.True(Directory.Exists(_root));
        Assert.False(Directory.Exists(Path.Combine(_root, "moved")));
    }

    [Fact]
    public async Task Write_with_a_traversal_path_lands_inside_the_root()
    {
        await using (var handle = await _fileSystem.OpenAsync("/../evil.txt", FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate, null, Ct))
            await handle.WriteAsync(0, new byte[] { 1 }, Ct);

        Assert.True(File.Exists(Path.Combine(_root, "evil.txt")));
        Assert.False(File.Exists(Path.Combine(_tempDirectory, "evil.txt")));
    }

    [Fact]
    public async Task List_of_a_subdirectory_has_no_dot_entries()
    {
        // "." and ".." of a listing are added by the protocol (SftpFileSystemAdapter), inside the root.
        Directory.CreateDirectory(Path.Combine(_root, "sub"));
        File.WriteAllText(Path.Combine(_root, "sub", "a.txt"), "a");

        var names = new List<string>();
        await foreach (var entry in _fileSystem.ListAsync("/sub", Ct))
            names.Add(entry.Name);

        Assert.Equal(["a.txt"], names);
    }
}
