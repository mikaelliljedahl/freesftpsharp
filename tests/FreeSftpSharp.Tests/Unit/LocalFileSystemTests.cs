using SshServer.Filesystem.LocalDisk;

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
    public void NormalizeVirtualPath_returns_a_rooted_path_without_dot_segments(string input, string expected)
    {
        Assert.Equal(expected, LocalFileSystem.NormalizeVirtualPath(input));
    }

    [Fact]
    public void NormalizeVirtualPath_of_null_is_root()
    {
        Assert.Equal("/", LocalFileSystem.NormalizeVirtualPath(null));
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
    public void GetPhysicalPath_cannot_reach_a_sibling_directory_with_the_same_prefix()
    {
        var sibling = _root + "-sibling"; // for example /tmp/x/root-sibling next to /tmp/x/root
        Directory.CreateDirectory(sibling);
        File.WriteAllText(Path.Combine(sibling, "secret.txt"), "secret");

        var physical = _fileSystem.GetPhysicalPath("/../root-sibling/secret.txt");

        Assert.Equal(Path.Combine(_root, "root-sibling", "secret.txt"), physical);
        Assert.False(_fileSystem.FileExists("/../root-sibling/secret.txt"));
    }

    [Fact]
    public void Root_with_a_trailing_separator_gives_the_same_paths()
    {
        var withSeparator = new LocalFileSystem(_root + Path.DirectorySeparatorChar);

        Assert.Equal(_root, withSeparator.GetPhysicalPath("/"));
        Assert.Equal(Path.Combine(_root, "a"), withSeparator.GetPhysicalPath("/../a"));
    }

    [Fact]
    public void File_outside_the_root_is_not_visible()
    {
        File.WriteAllText(Path.Combine(_tempDirectory, "config.db"), "secret");

        Assert.False(_fileSystem.FileExists("/../config.db"));
        Assert.False(_fileSystem.FileExists("..\\config.db"));
        Assert.Throws<FileNotFoundException>(() => _fileSystem.OpenStreamRead("/../config.db").Dispose());
    }

    [Theory]
    [InlineData("/")]
    [InlineData("")]
    [InlineData("/..")]
    [InlineData("/../..")]
    public void RemoveDirectory_never_removes_the_root(string path)
    {
        Assert.False(_fileSystem.RemoveDirectory(path));
        Assert.True(Directory.Exists(_root));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/..")]
    public void MoveFileOrDirectory_never_moves_the_root(string path)
    {
        Assert.False(_fileSystem.MoveFileOrDirectory(path, "/moved"));
        Assert.True(Directory.Exists(_root));
        Assert.False(Directory.Exists(Path.Combine(_root, "moved")));
    }

    [Fact]
    public void Write_with_a_traversal_path_lands_inside_the_root()
    {
        using (var stream = _fileSystem.OpenStreamWrite("/../evil.txt", FileMode.Create))
            stream.WriteByte(1);

        Assert.True(File.Exists(Path.Combine(_root, "evil.txt")));
        Assert.False(File.Exists(Path.Combine(_tempDirectory, "evil.txt")));
    }

    [Fact]
    public void GetDirectories_of_a_subdirectory_has_a_parent_entry_inside_the_root()
    {
        Directory.CreateDirectory(Path.Combine(_root, "sub"));

        var parent = Assert.Single(_fileSystem.GetDirectories("/sub"), d => d.Name == "..");
        Assert.Equal("/", parent.FullName);
        Assert.DoesNotContain(_fileSystem.GetDirectories("/"), d => d.Name == "..");
    }
}
