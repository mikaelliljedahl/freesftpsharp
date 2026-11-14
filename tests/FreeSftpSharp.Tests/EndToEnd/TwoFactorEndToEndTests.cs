using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet;
using Renci.SshNet.Common;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.TwoFactor;
using SshServer.TwoFactor;
using static FreeSftpSharp.Tests.Infrastructure.OpenSshSftp;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>The SFTP server with the TOTP second factor of the tests (issue #63). The code limit is high: tests fail codes on purpose.</summary>
public sealed class TwoFactorSftpServerFixture : SftpServerFixture
{
    protected override TwoFactorService? CreateTwoFactor(TimeProvider time) => TwoFactorTestKit.CreateService(time, maxFailedCodes: 1000);
}

/// <summary>
/// The TOTP second factor over SSH (issue #63): after the password or the key the server answers with partial success
/// and asks for the verification code over keyboard-interactive (RFC 4256). SSH.NET with
/// <see cref="KeyboardInteractiveAuthenticationMethod"/> and OpenSSH <c>sftp</c> (password, then the code through the
/// askpass script). A wrong or reused code is refused, a recovery code works once, and a user without TOTP logs in as
/// before, without a prompt.
/// <para>
/// The tests change the default test user and set up a new secret for it; xUnit runs the tests of one class one after
/// the other. The codes use the real clock, as an authenticator app does.
/// </para>
/// </summary>
public sealed class TwoFactorEndToEndTests : IClassFixture<TwoFactorSftpServerFixture>
{
    private const string SessionEndMarker = "Remote working directory: /";

    private readonly TwoFactorSftpServerFixture _server;

    public TwoFactorEndToEndTests(TwoFactorSftpServerFixture server)
    {
        _server = server;
    }

    private TwoFactorService TwoFactor => _server.TwoFactor!;

    private User User => _server.Repository.GetUser(_server.Username);

    private TwoFactorSubject Subject => TwoFactorSubject.ForUser(User);

    /// <summary>Sets the login methods and a key of the default user and gives it a new second factor (or none).</summary>
    private async Task<(string Secret, IReadOnlyList<string> RecoveryCodes, TestUserKey Key)> ConfigureUserAsync(bool totp,
        AuthMethods allowed = AuthMethods.All, params AuthMethods[] steps)
    {
        var key = TestUserKeys.Ed25519();
        var user = User;
        user.PublicKeys = [key.Entry];
        user.AllowedAuthMethods = allowed;
        user.RequireAllOf = steps.Length == 0 ? null : steps.ToList();
        Assert.True(_server.Repository.UpdateUser(user));

        await TwoFactor.ResetAsync(Subject, TestContext.Current.CancellationToken);
        if (!totp)
            return ("", [], key);
        var (secret, codes) = await TwoFactorTestKit.EnrolAsync(TwoFactor, Subject, TimeProvider.System, _server.Username);
        return (secret, codes, key);
    }

    private static string CurrentCode(string secret) => TwoFactorTestKit.Code(secret, DateTimeOffset.UtcNow);

    private SftpClient CreateClient(params AuthenticationMethod[] methods)
    {
        var info = new ConnectionInfo(SftpServerFixture.Host, _server.Port, _server.Username, methods) { Timeout = TimeSpan.FromSeconds(15) };
        return new SftpClient(info);
    }

    private PasswordAuthenticationMethod PasswordMethod(string? password = null) => new(_server.Username, password ?? _server.Password);

    private PrivateKeyAuthenticationMethod KeyMethod(TestUserKey key) => new(_server.Username, key.ToPrivateKeyFile());

    /// <summary>Answers "Verification code" with <paramref name="code"/> and every other prompt with the password; counts the prompts.</summary>
    private KeyboardInteractiveAuthenticationMethod CodeMethod(string code, List<string>? prompts = null)
    {
        var method = new KeyboardInteractiveAuthenticationMethod(_server.Username);
        method.AuthenticationPrompt += (_, e) =>
        {
            foreach (var prompt in e.Prompts)
            {
                prompts?.Add(prompt.Request);
                prompt.Response = prompt.Request.Contains("Verification code", StringComparison.Ordinal) ? code : _server.Password;
            }
        };
        return method;
    }

    [Fact]
    public async Task SshNet_with_the_password_and_the_code_logs_in()
    {
        var (secret, _, _) = await ConfigureUserAsync(totp: true);
        var prompts = new List<string>();

        using var client = CreateClient(PasswordMethod(), CodeMethod(CurrentCode(secret), prompts));
        client.Connect();

        Assert.True(client.IsConnected);
        Assert.Equal("/", client.WorkingDirectory);
        Assert.Equal(new[] { "Verification code: " }, prompts);
        Assert.Contains(_server.Connections.GetAll(), c => c.Username == _server.Username && c.AuthMethod == "password,keyboard-interactive");
    }

    [Fact]
    public async Task SshNet_with_the_key_and_the_code_logs_in()
    {
        var (secret, _, key) = await ConfigureUserAsync(totp: true);

        using var client = CreateClient(KeyMethod(key), CodeMethod(CurrentCode(secret)));
        client.Connect();

        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task SshNet_with_only_the_password_is_refused_when_the_user_has_totp()
    {
        await ConfigureUserAsync(totp: true);

        using var client = CreateClient(PasswordMethod());

        Assert.ThrowsAny<SshAuthenticationException>(() => client.Connect());
    }

    [Fact]
    public async Task SshNet_with_a_wrong_code_is_refused()
    {
        var (secret, _, _) = await ConfigureUserAsync(totp: true);
        var wrong = ((int.Parse(CurrentCode(secret)) + 1) % 1_000_000).ToString("D6");

        using var client = CreateClient(PasswordMethod(), CodeMethod(wrong));

        Assert.ThrowsAny<SshAuthenticationException>(() => client.Connect());
    }

    [Fact]
    public async Task SshNet_with_a_wrong_password_never_gets_the_code_prompt()
    {
        var (secret, _, _) = await ConfigureUserAsync(totp: true);
        var prompts = new List<string>();

        using var client = CreateClient(PasswordMethod("wrong-password"), CodeMethod(CurrentCode(secret), prompts));

        Assert.ThrowsAny<SshAuthenticationException>(() => client.Connect());
        Assert.DoesNotContain(prompts, p => p.Contains("Verification code", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_code_works_for_one_login_only()
    {
        var (secret, _, _) = await ConfigureUserAsync(totp: true);
        var code = CurrentCode(secret);

        using (var first = CreateClient(PasswordMethod(), CodeMethod(code)))
        {
            first.Connect();
            Assert.True(first.IsConnected);
        }

        using var second = CreateClient(PasswordMethod(), CodeMethod(code));
        Assert.ThrowsAny<SshAuthenticationException>(() => second.Connect());
    }

    [Fact]
    public async Task A_recovery_code_works_once_at_the_code_prompt()
    {
        var (_, recovery, _) = await ConfigureUserAsync(totp: true);

        using (var first = CreateClient(PasswordMethod(), CodeMethod(recovery[0])))
        {
            first.Connect();
            Assert.True(first.IsConnected);
        }

        using var second = CreateClient(PasswordMethod(), CodeMethod(recovery[0]));
        Assert.ThrowsAny<SshAuthenticationException>(() => second.Connect());
    }

    [Fact]
    public async Task A_multi_step_login_with_the_key_then_keyboard_interactive_asks_for_the_code()
    {
        var (secret, _, key) = await ConfigureUserAsync(totp: true, AuthMethods.All, AuthMethods.PublicKey, AuthMethods.KeyboardInteractive);

        using (var password = CreateClient(PasswordMethod(), CodeMethod(CurrentCode(secret))))
            Assert.ThrowsAny<SshAuthenticationException>(() => password.Connect()); // the key is the first step

        using var client = CreateClient(KeyMethod(key), CodeMethod(CurrentCode(secret)));
        client.Connect();
        Assert.True(client.IsConnected);
        Assert.Contains(_server.Connections.GetAll(), c => c.AuthMethod == "publickey,keyboard-interactive");
    }

    [Fact]
    public async Task Without_totp_the_key_then_keyboard_interactive_asks_for_the_password()
    {
        var (_, _, key) = await ConfigureUserAsync(totp: false, AuthMethods.All, AuthMethods.PublicKey, AuthMethods.KeyboardInteractive);
        var prompts = new List<string>();

        using var client = CreateClient(KeyMethod(key), CodeMethod("unused", prompts));
        client.Connect();

        Assert.True(client.IsConnected);
        Assert.Equal(new[] { "Password: " }, prompts);
    }

    [Fact]
    public async Task A_user_without_totp_logs_in_with_the_password_alone_and_gets_no_prompt()
    {
        await ConfigureUserAsync(totp: false);
        var prompts = new List<string>();

        using var client = CreateClient(PasswordMethod(), CodeMethod("unused", prompts));
        client.Connect();

        Assert.True(client.IsConnected);
        Assert.Empty(prompts);
        Assert.Contains(_server.Connections.GetAll(), c => c.Username == _server.Username && c.AuthMethod == "password");
    }

    [Fact]
    public async Task After_a_reset_the_password_alone_is_enough_again()
    {
        await ConfigureUserAsync(totp: true);
        await TwoFactor.ResetAsync(Subject, TestContext.Current.CancellationToken);

        using var client = CreateClient(PasswordMethod());
        client.Connect();

        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task OpenSsh_asks_for_the_code_after_the_password_and_logs_in()
    {
        SkipIfUnavailable();
        var (secret, _, _) = await ConfigureUserAsync(totp: true);

        var result = await RunWithAskPassAsync(_server, CreateLocalDirectory(), AskPassScript(CurrentCode(secret)),
            ["PreferredAuthentications=password,keyboard-interactive", "LogLevel=DEBUG"], "pwd");

        Assert.True(result.StandardOutput.Contains(SessionEndMarker), $"The sftp session did not run to the end.{Environment.NewLine}{result}");
        var partial = result.StandardError.IndexOf("Authenticated using \"password\" with partial success", StringComparison.Ordinal);
        var code = result.StandardError.IndexOf("using \"keyboard-interactive\".", StringComparison.Ordinal);
        Assert.True(partial >= 0 && code > partial, result.ToString());
    }

    [Fact]
    public async Task OpenSsh_with_a_wrong_code_is_refused()
    {
        SkipIfUnavailable();
        await ConfigureUserAsync(totp: true);

        var result = await RunWithAskPassAsync(_server, CreateLocalDirectory(), AskPassScript("000000"),
            ["PreferredAuthentications=password,keyboard-interactive"], "pwd");

        Assert.False(result.StandardOutput.Contains(SessionEndMarker), $"The login must be refused.{Environment.NewLine}{result}");
    }

    /// <summary>An askpass script that answers the verification code prompt with <paramref name="code"/> and every other one with the password.</summary>
    private string AskPassScript(string code)
    {
        if (OperatingSystem.IsWindows())
            Assert.Skip("The keyboard-interactive askpass script is a POSIX shell script.");
        var path = Path.Combine(_server.TempDirectory, $"askpass-{Guid.NewGuid():N}.sh");
        File.WriteAllText(path,
            "#!/bin/sh\ncase \"$1\" in\n  *\"Verification code\"*) echo '" + code + "' ;;\n  *) echo '" + _server.Password + "' ;;\nesac\n");
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

    private string CreateLocalDirectory()
    {
        var local = Path.Combine(_server.TempDirectory, "local-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(local);
        return local;
    }
}
