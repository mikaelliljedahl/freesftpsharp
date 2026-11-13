using SshServerModule.Sftp;
using static FreeSftpSharp.Tests.Sftp.SftpEngineClient;

namespace FreeSftpSharp.Tests.Sftp;

/// <summary>SSH_FXP_REALPATH: the canonical path, always inside the user root.</summary>
public sealed class SftpRealPathTests : SftpEngineTestBase
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
    [InlineData("~", "/")]
    [InlineData("~/a", "/a")]
    [InlineData("/~", "/~")]
    public void NormalizePath_returns_the_canonical_path(string input, string expected)
    {
        Assert.Equal(expected, SftpFileSystemAdapter.NormalizePath(input));
    }

    [Fact]
    public void NormalizePath_only_uses_forward_slash_as_separator()
    {
        // REALPATH works on SFTP paths, where "\" is an ordinary character. LocalFileSystem treats "\"
        // as a separator later, so this path still cannot leave the user root.
        Assert.Equal("/..\\x", SftpFileSystemAdapter.NormalizePath("/..\\x"));
    }

    [Theory]
    [InlineData(".", "/")]
    [InlineData("/../..", "/")]
    [InlineData("/../config.db", "/config.db")]
    [InlineData("/missing/../dir", "/dir")]
    public void RealPath_request_gives_one_name_with_the_canonical_path(string input, string expected)
    {
        var response = Client.SendPath(SSH_FXP_REALPATH, input);

        var name = Assert.Single(response.Names());
        Assert.Equal(expected, name.Name);
    }
}
