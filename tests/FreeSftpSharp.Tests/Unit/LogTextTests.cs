using FxSsh.SshServerModule.Security;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>The log sanitizer of client values (CWE-117).</summary>
public sealed class LogTextTests
{
    [Theory]
    [InlineData("/plain/path.txt", "/plain/path.txt")]
    [InlineData("a\nb", "a\\nb")]
    [InlineData("a\r\nb\tc", "a\\r\\nb\\tc")]
    [InlineData("esc\u001b[31m", "esc\\u001b[31m")]
    [InlineData("räksmörgås", "räksmörgås")]
    public void Control_characters_are_escaped(string input, string expected) => Assert.Equal(expected, LogText.Clean(input));

    [Fact]
    public void Null_stays_null() => Assert.Null(LogText.Clean(null));
}
