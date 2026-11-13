using FxSshSftpServer.Security;

namespace FreeSftpSharp.Tests.Unit;

public sealed class AdminPasswordCommandTests
{
    [Fact]
    public void Is_requested_only_with_the_switch()
    {
        Assert.True(AdminPasswordCommand.IsRequested(["--hash-admin-password"]));
        Assert.False(AdminPasswordCommand.IsRequested([]));
        Assert.False(AdminPasswordCommand.IsRequested(["--urls", "http://localhost:5000"]));
    }

    [Fact]
    public void Prints_a_hash_that_verifies_the_password_read_from_input()
    {
        var output = new StringWriter();
        var error = new StringWriter();

        var exitCode = AdminPasswordCommand.Run(new StringReader("my admin password\n"), output, error, interactive: false);

        Assert.Equal(0, exitCode);
        var hashLine = output.ToString().Split('\n').Single(l => l.StartsWith("AdminAuth__PasswordHash=", StringComparison.Ordinal));
        var hash = hashLine["AdminAuth__PasswordHash=".Length..].Trim();
        Assert.True(AdminPasswordHasher.Verify("my admin password", hash));
        Assert.DoesNotContain("my admin password", output.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("\n")]
    [InlineData("short\n")]
    public void Rejects_an_empty_or_too_short_password(string input)
    {
        var output = new StringWriter();
        var error = new StringWriter();

        var exitCode = AdminPasswordCommand.Run(new StringReader(input), output, error, interactive: false);

        Assert.NotEqual(0, exitCode);
        Assert.DoesNotContain("PBKDF2", output.ToString());
        Assert.NotEmpty(error.ToString());
    }
}
