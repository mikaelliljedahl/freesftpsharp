using SshServer.Webhooks;

namespace FreeSftpSharp.Tests.Webhooks;

public sealed class PathGlobTests
{
    [Theory]
    [InlineData("/incoming/*.csv", "/incoming/a.csv", true)]
    [InlineData("/incoming/*.csv", "/incoming/sub/a.csv", false)]
    [InlineData("/incoming/**/*.csv", "/incoming/a.csv", true)]
    [InlineData("/incoming/**/*.csv", "/incoming/x/y/a.csv", true)]
    [InlineData("/incoming/**", "/incoming/x/y", true)]
    [InlineData("/incoming/**", "/outgoing/x", false)]
    [InlineData("/**/denied*", "/t-1/denied.txt", true)]
    [InlineData("/file?.txt", "/file1.txt", true)]
    [InlineData("/file?.txt", "/file/.txt", false)]
    [InlineData("/a.txt", "/A.txt", false)]
    [InlineData("/a+b(1).txt", "/a+b(1).txt", true)]
    public void Matches_the_whole_virtual_path(string pattern, string path, bool expected)
    {
        Assert.Equal(expected, PathGlob.Parse(pattern).IsMatch(path));
    }
}
