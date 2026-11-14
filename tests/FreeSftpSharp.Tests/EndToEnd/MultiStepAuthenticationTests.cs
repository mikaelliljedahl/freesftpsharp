using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet;
using Renci.SshNet.Common;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using static FreeSftpSharp.Tests.Infrastructure.OpenSshSftp;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// Multi-step login (issue #58, <see cref="User.RequireAllOf"/>): the server answers the first method with partial
/// success, and the client must give the next one. SSH.NET with both methods and OpenSSH <c>sftp</c> (key, then the
/// password prompt) log in; one method alone is refused. Ed25519 key login with OpenSSH too.
/// <para>
/// The tests change the default test user (OpenSSH logs in as that user, with the password of its askpass script).
/// xUnit runs the tests of one class one after the other, so they do not disturb each other.
/// </para>
/// </summary>
public sealed class MultiStepAuthenticationTests : IClassFixture<SftpServerFixture>
{
    private const string SessionEndMarker = "Remote working directory: /";

    private readonly SftpServerFixture _server;

    public MultiStepAuthenticationTests(SftpServerFixture server)
    {
        _server = server;
    }

    /// <summary>Sets the keys and the login methods of the default user; returns its key.</summary>
    private TestUserKey ConfigureUser(AuthMethods allowed = AuthMethods.All, params AuthMethods[] steps)
    {
        var key = TestUserKeys.Ed25519();
        var user = _server.Repository.GetUser(_server.Username);
        user.PublicKeys = [key.Entry];
        user.AllowedAuthMethods = allowed;
        user.RequireAllOf = steps.Length == 0 ? null : steps.ToList();
        Assert.True(_server.Repository.UpdateUser(user));
        return key;
    }

    private SftpClient CreateClient(params AuthenticationMethod[] methods)
    {
        var info = new ConnectionInfo(SftpServerFixture.Host, _server.Port, _server.Username, methods) { Timeout = TimeSpan.FromSeconds(15) };
        return new SftpClient(info);
    }

    private PrivateKeyAuthenticationMethod KeyMethod(TestUserKey key) => new(_server.Username, key.ToPrivateKeyFile());

    private PasswordAuthenticationMethod PasswordMethod(string? password = null) => new(_server.Username, password ?? _server.Password);

    [Fact]
    public void SshNet_with_the_key_and_the_password_logs_in()
    {
        var key = ConfigureUser(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);

        using var client = CreateClient(KeyMethod(key), PasswordMethod());
        client.Connect();

        Assert.True(client.IsConnected);
        Assert.Equal("/", client.WorkingDirectory);
        Assert.Contains(_server.Connections.GetAll(), c => c.Username == _server.Username && c.AuthMethod == "publickey,password");
    }

    [Fact]
    public void SshNet_with_the_password_first_logs_in_when_the_user_needs_the_password_first()
    {
        var key = ConfigureUser(AuthMethods.All, AuthMethods.Password, AuthMethods.PublicKey);

        using var client = CreateClient(PasswordMethod(), KeyMethod(key));
        client.Connect();

        Assert.True(client.IsConnected);
    }

    [Fact]
    public void SshNet_with_only_the_key_is_refused()
    {
        var key = ConfigureUser(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);

        using var client = CreateClient(KeyMethod(key));

        Assert.ThrowsAny<SshAuthenticationException>(() => client.Connect());
    }

    [Fact]
    public void SshNet_with_only_the_password_is_refused()
    {
        ConfigureUser(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);

        using var client = CreateClient(PasswordMethod());

        Assert.ThrowsAny<SshAuthenticationException>(() => client.Connect());
    }

    [Fact]
    public void SshNet_with_the_key_and_a_wrong_password_is_refused()
    {
        var key = ConfigureUser(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);

        using var client = CreateClient(KeyMethod(key), PasswordMethod("wrong-password"));

        Assert.ThrowsAny<SshAuthenticationException>(() => client.Connect());
    }

    [Fact]
    public void SshNet_with_another_key_and_the_password_is_refused()
    {
        ConfigureUser(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);

        using var client = CreateClient(KeyMethod(TestUserKeys.Ed25519()), PasswordMethod());

        Assert.ThrowsAny<SshAuthenticationException>(() => client.Connect());
    }

    [Fact]
    public async Task OpenSsh_is_asked_for_the_password_after_the_key_and_logs_in()
    {
        SkipIfUnavailable();
        var key = ConfigureUser(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);

        var result = await RunWithOptionsAsync(_server, CreateLocalDirectory(), KeyOptions(key, "LogLevel=DEBUG"), "pwd");

        AssertSessionCompleted(result);
        // OpenSSH logs the partial success of the key, then the password (asked through the askpass script).
        var partial = result.StandardError.IndexOf("Authenticated using \"publickey\" with partial success", StringComparison.Ordinal);
        var password = result.StandardError.IndexOf("using \"password\".", StringComparison.Ordinal);
        Assert.True(partial >= 0 && password > partial, result.ToString());
    }

    [Fact]
    public async Task OpenSsh_with_only_the_key_is_refused()
    {
        SkipIfUnavailable();
        var key = ConfigureUser(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);

        var result = await RunWithOptionsAsync(_server, CreateLocalDirectory(), KeyOptions(key, "PasswordAuthentication=no"), "pwd");

        AssertRefused(result);
    }

    [Fact]
    public async Task OpenSsh_with_only_the_password_is_refused()
    {
        SkipIfUnavailable();
        ConfigureUser(AuthMethods.All, AuthMethods.PublicKey, AuthMethods.Password);

        // The default options of the harness: password only, no public key.
        var result = await RunAsync(_server, CreateLocalDirectory(), "pwd");

        AssertRefused(result);
    }

    [Fact]
    public async Task OpenSsh_logs_in_with_an_ed25519_key_alone_when_one_method_is_enough()
    {
        SkipIfUnavailable();
        var key = ConfigureUser(AuthMethods.PublicKey);

        var result = await RunWithOptionsAsync(_server, CreateLocalDirectory(), KeyOptions(key, "PasswordAuthentication=no"), "pwd");

        AssertSessionCompleted(result);
    }

    [Fact]
    public async Task OpenSsh_with_the_right_password_is_refused_for_a_key_only_user()
    {
        SkipIfUnavailable();
        ConfigureUser(AuthMethods.PublicKey);

        var result = await RunAsync(_server, CreateLocalDirectory(), "pwd");

        AssertRefused(result);
    }

    /// <summary>The ssh options for a login with <paramref name="key"/> first and then the password.</summary>
    private string[] KeyOptions(TestUserKey key, params string[] more) =>
        new[]
        {
            "PubkeyAuthentication=yes",
            "PreferredAuthentications=publickey,password",
            "IdentitiesOnly=yes",
            "IdentityFile=" + key.WriteTo(_server.TempDirectory),
        }.Concat(more).ToArray();

    private string CreateLocalDirectory()
    {
        var local = Path.Combine(_server.TempDirectory, "local-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(local);
        return local;
    }

    private static void AssertSessionCompleted(Result result)
    {
        Assert.True(result.StandardOutput.Contains(SessionEndMarker), $"The sftp session did not run to the end.{Environment.NewLine}{result}");
    }

    private static void AssertRefused(Result result)
    {
        Assert.False(result.StandardOutput.Contains(SessionEndMarker), $"The login must be refused.{Environment.NewLine}{result}");
        Assert.Contains("Permission denied", result.StandardError);
    }
}
