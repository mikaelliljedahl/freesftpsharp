using System.Reflection;
using FxSsh.SshServerModule.Cli;

namespace FreeSftpSharp.Tests.Unit;

public sealed class VersionCommandTests
{
    [Theory]
    [InlineData("--version", true)]
    [InlineData("--VERSION", true)]
    [InlineData("--port", false)]
    [InlineData("user", false)]
    public void Only_a_lone_version_switch_is_a_request(string argument, bool expected)
    {
        Assert.Equal(expected, VersionCommand.IsRequested([argument]));
    }

    [Fact]
    public void No_arguments_and_extra_arguments_are_not_a_request()
    {
        Assert.False(VersionCommand.IsRequested([]));
        Assert.False(VersionCommand.IsRequested(["--version", "--port", "22"]));
    }

    [Fact]
    public void The_build_metadata_after_a_plus_is_removed()
    {
        var version = VersionCommand.Describe(typeof(VersionCommand).Assembly);

        Assert.False(string.IsNullOrWhiteSpace(version));
        Assert.DoesNotContain('+', version);
    }
}
