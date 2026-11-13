using FreeSftpSharp.Tests.Infrastructure;
using SshServer.Filesystem.LocalDisk;

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

    private string InRoot(string relative) => Path.Combine(_root, relative.Replace('/', Path.DirectorySeparatorChar));

    [Fact]
    public void Link_to_a_directory_outside_the_root_is_refused_for_every_operation()
    {
        FileLinks.CreateDirectoryLink(InRoot("out"), _outside);

        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.GetPhysicalPath("/out"));
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.GetPhysicalPath("/out/secret.txt"));
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.DirectoryExists("/out"));
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.FileExists("/out/secret.txt"));
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.GetInfo("/out"));
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.GetInfo("/out/secret.txt"));
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.GetFiles("/out").ToList());
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.GetDirectories("/out").ToList());
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.OpenFile("/out/secret.txt", FileMode.Open, FileAccess.Read).Dispose());
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.OpenFile("/out/new.txt", FileMode.Create, FileAccess.Write).Dispose());
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.OpenStreamWrite("/out/secret.txt", FileMode.Create).Dispose());
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.RemoveFile("/out/secret.txt"));
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.SetFileLength("/out/secret.txt", 0));
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.SetPermissions("/out/secret.txt", 0x1FF));
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.SetTimes("/out/secret.txt", DateTime.UnixEpoch, DateTime.UnixEpoch));
        Assert.False(_fileSystem.MakeDirectory("/out/newdir"));
        Assert.False(_fileSystem.MoveFileOrDirectory("/out/secret.txt", "/stolen.txt"));
        File.WriteAllText(InRoot("mine.txt"), "mine");
        Assert.False(_fileSystem.MoveFileOrDirectory("/mine.txt", "/out/mine.txt"));

        Assert.Equal(Secret, File.ReadAllText(_secretFile));
        Assert.Equal(["secret.txt"], Directory.GetFileSystemEntries(_outside).Select(Path.GetFileName));
        Assert.False(File.Exists(InRoot("stolen.txt")));
    }

    [Fact]
    public void Relative_link_that_leaves_the_root_is_refused()
    {
        FileLinks.CreateDirectoryLink(InRoot("up"), Path.Combine("..", "outside"));

        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.FileExists("/up/secret.txt"));
    }

    [Fact]
    public void Link_in_a_subdirectory_to_the_parent_of_the_root_is_refused()
    {
        Directory.CreateDirectory(InRoot("a/b"));
        FileLinks.CreateDirectoryLink(InRoot("a/b/top"), Path.Combine("..", "..", ".."));

        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.FileExists("/a/b/top/outside/secret.txt"));
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.GetDirectories("/a/b/top").ToList());
    }

    [Fact]
    public void Chain_of_links_that_ends_outside_the_root_is_refused()
    {
        FileLinks.CreateDirectoryLink(InRoot("second"), _outside);
        FileLinks.CreateDirectoryLink(InRoot("first"), InRoot("second"));

        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.FileExists("/first/secret.txt"));
    }

    [Fact]
    public void Link_to_a_file_outside_the_root_is_refused()
    {
        FileLinks.CreateFileLink(InRoot("secret-link.txt"), _secretFile);

        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.FileExists("/secret-link.txt"));
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.OpenFile("/secret-link.txt", FileMode.Open, FileAccess.Read).Dispose());
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.OpenFile("/secret-link.txt", FileMode.Open, FileAccess.Write).Dispose());
        Assert.Equal(Secret, File.ReadAllText(_secretFile));
    }

    [Fact]
    public void Dangling_link_to_a_missing_file_outside_the_root_cannot_create_it()
    {
        var target = Path.Combine(_outside, "created.txt");
        FileLinks.CreateFileLink(InRoot("dangling.txt"), target);

        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.OpenFile("/dangling.txt", FileMode.OpenOrCreate, FileAccess.Write).Dispose());
        Assert.False(File.Exists(target));
    }

    [Fact]
    public void Link_to_a_directory_inside_the_root_keeps_working()
    {
        Directory.CreateDirectory(InRoot("real"));
        File.WriteAllText(InRoot("real/file.txt"), "inside");
        FileLinks.CreateDirectoryLink(InRoot("alias"), InRoot("real"));
        FileLinks.CreateDirectoryLink(InRoot("relative-alias"), "real");

        Assert.True(_fileSystem.DirectoryExists("/alias"));
        Assert.True(_fileSystem.FileExists("/alias/file.txt"));
        Assert.True(_fileSystem.FileExists("/relative-alias/file.txt"));
        Assert.Contains(_fileSystem.GetFiles("/alias"), f => f.Name == "file.txt");
        using (var stream = _fileSystem.OpenFile("/alias/new.txt", FileMode.Create, FileAccess.Write))
            stream.WriteByte(1);
        Assert.True(File.Exists(InRoot("real/new.txt")));
        Assert.True(_fileSystem.MakeDirectory("/alias/sub"));
        Assert.True(Directory.Exists(InRoot("real/sub")));
    }

    [Fact]
    public void Link_to_a_file_inside_the_root_keeps_working()
    {
        File.WriteAllText(InRoot("file.txt"), "inside");
        FileLinks.CreateFileLink(InRoot("file-link.txt"), "file.txt");

        using var reader = new StreamReader(_fileSystem.OpenFile("/file-link.txt", FileMode.Open, FileAccess.Read));
        Assert.Equal("inside", reader.ReadToEnd());
    }

    [Fact]
    public void Link_that_goes_out_and_comes_back_inside_the_root_keeps_working()
    {
        Directory.CreateDirectory(InRoot("real"));
        File.WriteAllText(InRoot("real/file.txt"), "inside");
        FileLinks.CreateDirectoryLink(InRoot("roundtrip"), Path.Combine("..", "root", "real"));

        Assert.True(_fileSystem.FileExists("/roundtrip/file.txt"));
    }

    [Fact]
    public void Root_reached_through_a_link_to_its_parent_cannot_be_removed_moved_or_changed()
    {
        FileLinks.CreateDirectoryLink(InRoot("parent"), _tempDirectory);

        Assert.False(_fileSystem.RemoveDirectory("/parent/root"));
        Assert.False(_fileSystem.MoveFileOrDirectory("/parent/root", "/moved"));
        Assert.Throws<UnauthorizedAccessException>(() => _fileSystem.SetPermissions("/parent/root", 0));
        Assert.True(Directory.Exists(_root));
        Assert.True(Directory.Exists(InRoot("parent")));
    }

    [Fact]
    public void Link_to_the_root_can_be_removed_and_the_root_stays()
    {
        FileLinks.CreateDirectoryLink(InRoot("self"), _root);

        Assert.True(_fileSystem.RemoveDirectory("/self"));

        Assert.False(Path.Exists(InRoot("self")));
        Assert.True(Directory.Exists(_root));
    }

    [Fact]
    public void Root_that_is_a_link_keeps_working()
    {
        var linkedRoot = Path.Combine(_tempDirectory, "root-link");
        FileLinks.CreateDirectoryLink(linkedRoot, _root);
        File.WriteAllText(InRoot("file.txt"), "inside");
        var fileSystem = new LocalFileSystem(linkedRoot);

        Assert.True(fileSystem.FileExists("/file.txt"));
        Assert.True(fileSystem.DirectoryExists("/"));
    }

    [Fact]
    public void Path_below_a_file_or_a_missing_directory_is_not_found_and_not_refused()
    {
        File.WriteAllText(InRoot("file.txt"), "x");

        Assert.False(_fileSystem.FileExists("/file.txt/child"));
        Assert.False(_fileSystem.FileExists("/missing/child"));
        Assert.Null(_fileSystem.GetInfo("/missing/child"));
    }

    [Fact]
    public void Link_loop_gives_an_error_and_no_hang()
    {
        if (OperatingSystem.IsWindows())
            Assert.Skip("A link loop is a POSIX test; junctions to a missing target cannot be created.");
        Directory.CreateSymbolicLink(InRoot("loop-a"), "loop-b");
        Directory.CreateSymbolicLink(InRoot("loop-b"), "loop-a");

        var ex = Record.Exception(() => _fileSystem.FileExists("/loop-a/x"));

        Assert.True(ex is IOException or UnauthorizedAccessException, $"Unexpected: {ex}");
    }
}
