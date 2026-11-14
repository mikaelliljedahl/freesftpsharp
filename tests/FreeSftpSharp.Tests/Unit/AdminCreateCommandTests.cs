using FreeSftpSharp.Tests.Infrastructure;
using FxSshSftpServer.Security;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.Unit;

/// <summary><c>FxSshSftpServer --create-admin &lt;name&gt;</c> creates a super admin in the settings database (#60).</summary>
public sealed class AdminCreateCommandTests
{
    private readonly InMemoryAdminStore _store = new();
    private readonly AdminAdministrationService _service;
    private readonly StringWriter _output = new();
    private readonly StringWriter _error = new();

    public AdminCreateCommandTests()
    {
        _service = new AdminAdministrationService(_store, new InMemorySettingsRepository(new ServerSettings()),
            hashIterations: PasswordHasher.MinimumIterations);
    }

    private Task<int> RunAsync(string stdin, params string[] args) =>
        AdminCreateCommand.RunAsync(args, _service, new StringReader(stdin), _output, _error, interactive: false,
            TestContext.Current.CancellationToken);

    [Fact]
    public void The_switch_is_recognized()
    {
        Assert.True(AdminCreateCommand.IsRequested(["--create-admin", "alice"]));
        Assert.False(AdminCreateCommand.IsRequested(["--hash-admin-password"]));
    }

    [Fact]
    public async Task A_super_admin_is_created_with_the_password_from_stdin_which_is_never_printed()
    {
        var exitCode = await RunAsync("long-enough-1\n", "--create-admin", "alice");

        Assert.Equal(0, exitCode);
        var admin = await _store.GetAdminAsync("alice", TestContext.Current.CancellationToken);
        Assert.NotNull(admin);
        Assert.Equal(AdminPermissions.SuperAdmin, admin.Permissions);
        Assert.True(PasswordHasher.Verify("long-enough-1", admin.PasswordHash));
        Assert.DoesNotContain("long-enough-1", _output.ToString() + _error.ToString());
    }

    [Fact]
    public async Task Without_a_name_on_redirected_input_the_usage_is_shown()
    {
        Assert.Equal(1, await RunAsync("long-enough-1\n", "--create-admin"));
        Assert.Contains("Usage", _error.ToString());
        Assert.False(await _store.AnyAdminAsync(TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("short\n", "at least 8")]
    [InlineData("", "at least 8")]
    public async Task A_short_password_is_refused(string stdin, string message)
    {
        Assert.Equal(1, await RunAsync(stdin, "--create-admin", "alice"));
        Assert.Contains(message, _error.ToString());
    }

    [Fact]
    public async Task An_existing_name_is_refused()
    {
        Assert.Equal(0, await RunAsync("long-enough-1\n", "--create-admin", "alice"));

        Assert.Equal(1, await RunAsync("long-enough-2\n", "--create-admin", "ALICE"));
        Assert.Contains("already exists", _error.ToString());
    }
}
