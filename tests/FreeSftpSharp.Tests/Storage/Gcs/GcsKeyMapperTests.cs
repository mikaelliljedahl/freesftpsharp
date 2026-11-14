using SshServer.Filesystem.Gcs;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage.Gcs;

/// <summary>The mapping of virtual paths to object names below the key prefix (<see cref="GcsKeyMapper"/>).</summary>
public sealed class GcsKeyMapperTests
{
    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("/", "")]
    [InlineData("users/alice", "users/alice/")]
    [InlineData("/users//alice/", "users/alice/")]
    [InlineData("users\\alice", "users/alice/")]
    public void Key_prefix_is_normalized(string? keyPrefix, string expected)
    {
        Assert.Equal(expected, new GcsKeyMapper(keyPrefix).Prefix);
    }

    [Theory]
    [InlineData("users/alice", "/a.txt", "users/alice/a.txt")]
    [InlineData("users/alice", "/dir/sub/räksmörgås ✓.txt", "users/alice/dir/sub/räksmörgås ✓.txt")]
    [InlineData("", "/a.txt", "a.txt")]
    public void File_key_is_the_path_below_the_prefix(string keyPrefix, string path, string expected)
    {
        Assert.Equal(expected, new GcsKeyMapper(keyPrefix).FileKey(path));
    }

    [Theory]
    [InlineData("users/alice", "/", "users/alice/")]
    [InlineData("users/alice", "/dir", "users/alice/dir/")]
    [InlineData("", "/", "")]
    [InlineData("", "/dir/sub", "dir/sub/")]
    public void Directory_prefix_ends_with_a_slash(string keyPrefix, string path, string expected)
    {
        Assert.Equal(expected, new GcsKeyMapper(keyPrefix).DirectoryPrefix(path));
    }

    [Theory]
    [InlineData("p/dir/", "p/dir/a.txt", "a.txt")]
    [InlineData("p/dir/", "p/dir/sub/", "sub")]
    [InlineData("p/dir/", "p/dir/", null)]        // the marker of the directory itself
    [InlineData("p/dir/", "p/dir//", null)]       // an empty segment
    [InlineData("p/dir/", "p/dir/./", null)]
    [InlineData("p/dir/", "p/dir/../", null)]
    [InlineData("p/dir/", "p/dir/a\\b.txt", null)] // "\" is a separator of the virtual paths
    [InlineData("p/dir/", "p/other/a.txt", null)]
    public void Child_name_of_a_listed_key(string directoryPrefix, string key, string? expected)
    {
        Assert.Equal(expected, GcsKeyMapper.ChildName(directoryPrefix, key));
    }

    [Fact]
    public void Key_longer_than_1024_bytes_is_an_invalid_path()
    {
        var mapper = new GcsKeyMapper("p");

        var ex = Assert.Throws<FileSystemException>(() => mapper.FileKey("/" + new string('ä', 512)));

        Assert.Equal(FileSystemError.InvalidPath, ex.Error);
        Assert.Equal(1024, System.Text.Encoding.UTF8.GetByteCount(mapper.FileKey("/" + new string('x', 1022))));
    }
}
