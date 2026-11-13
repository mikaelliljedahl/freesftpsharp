using SshServerModule.Services;

namespace FreeSftpSharp.Tests.Unit;

public sealed class SftpSubsystemNormalizePathTests
{
    [Theory]
    [InlineData("", "/")]
    [InlineData(".", "/")]
    [InlineData("/", "/")]
    [InlineData("..", "/")]
    [InlineData("/..", "/")]
    [InlineData("../..", "/")]
    [InlineData("/a/../..", "/")]
    [InlineData("/../../etc/passwd", "/etc/passwd")]
    [InlineData("/a/b/../../../../c", "/c")]
    [InlineData("a/b", "/a/b")]
    [InlineData("/a/./b/", "/a/b")]
    [InlineData("//double//slash", "/double/slash")]
    [InlineData("/.../x", "/.../x")]
    [InlineData("/dir/sub/..", "/dir")]
    public void NormalizePath_returns_the_canonical_path(string input, string expected)
    {
        Assert.Equal(expected, SftpSubsystem.NormalizePath(input));
    }

    [Fact]
    public void NormalizePath_only_uses_forward_slash_as_separator()
    {
        // REALPATH works on SFTP paths, where "\" is an ordinary character. LocalFileSystem treats "\"
        // as a separator later, so this path still cannot leave the user root.
        Assert.Equal("/..\\x", SftpSubsystem.NormalizePath("/..\\x"));
    }
}
