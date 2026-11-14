using SshServer.Filesystem.AzureBlob;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage.AzureBlob;

/// <summary>The mapping of virtual paths to blob names below the name prefix (<see cref="AzureBlobNameMapper"/>).</summary>
public sealed class AzureBlobNameMapperTests
{
    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("/", "")]
    [InlineData("users/alice", "users/alice/")]
    [InlineData("/users//alice/", "users/alice/")]
    [InlineData("users\\alice", "users/alice/")]
    public void Name_prefix_is_normalized(string? keyPrefix, string expected)
    {
        Assert.Equal(expected, new AzureBlobNameMapper(keyPrefix).Prefix);
    }

    [Theory]
    [InlineData("users/alice", "/a.txt", "users/alice/a.txt")]
    [InlineData("users/alice", "/dir/sub/räksmörgås ✓.txt", "users/alice/dir/sub/räksmörgås ✓.txt")]
    [InlineData("", "/a.txt", "a.txt")]
    public void File_name_is_the_path_below_the_prefix(string keyPrefix, string path, string expected)
    {
        Assert.Equal(expected, new AzureBlobNameMapper(keyPrefix).FileName(path));
    }

    [Theory]
    [InlineData("users/alice", "/", "users/alice/")]
    [InlineData("users/alice", "/dir", "users/alice/dir/")]
    [InlineData("", "/", "")]
    [InlineData("", "/dir/sub", "dir/sub/")]
    public void Directory_prefix_ends_with_a_slash(string keyPrefix, string path, string expected)
    {
        Assert.Equal(expected, new AzureBlobNameMapper(keyPrefix).DirectoryPrefix(path));
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
    public void Child_name_of_a_listed_blob(string directoryPrefix, string blobName, string? expected)
    {
        Assert.Equal(expected, AzureBlobNameMapper.ChildName(directoryPrefix, blobName));
    }

    [Fact]
    public void A_name_of_more_than_1024_characters_is_an_invalid_path()
    {
        var mapper = new AzureBlobNameMapper("p");

        Assert.Equal(1024, mapper.FileName("/" + new string('a', 1024 - 2)).Length);
        var ex = Assert.Throws<FileSystemException>(() => mapper.FileName("/" + new string('a', 1024 - 1)));
        Assert.Equal(FileSystemError.InvalidPath, ex.Error);
        Assert.Throws<FileSystemException>(() => mapper.DirectoryPrefix("/" + new string('a', 1024)));
    }

    [Fact]
    public void A_name_with_more_than_254_segments_is_an_invalid_path()
    {
        var mapper = new AzureBlobNameMapper("");

        mapper.FileName("/" + string.Join('/', Enumerable.Repeat("a", 254)));
        var ex = Assert.Throws<FileSystemException>(() => mapper.FileName("/" + string.Join('/', Enumerable.Repeat("a", 255))));
        Assert.Equal(FileSystemError.InvalidPath, ex.Error);
    }

    [Fact]
    public void A_file_name_that_ends_with_a_dot_is_an_invalid_path()
    {
        var ex = Assert.Throws<FileSystemException>(() => new AzureBlobNameMapper("p").FileName("/dir/a."));

        Assert.Equal(FileSystemError.InvalidPath, ex.Error);
    }
}
