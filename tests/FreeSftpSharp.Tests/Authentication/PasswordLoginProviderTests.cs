using System.Net;
using FreeSftpSharp.Tests.Infrastructure;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Groups;
using SshServerModule.Authentication;

namespace FreeSftpSharp.Tests.Authentication;

/// <summary>The password login of WebDAV and the other protocols (#71) with the authentication providers (#64).</summary>
public sealed class PasswordLoginProviderTests
{
    private readonly InMemorySettingsRepository _repository = new(new ServerSettings());
    private readonly FakeAuthenticationProvider _external;
    private readonly PasswordLoginService _logins;

    public PasswordLoginProviderTests()
    {
        _repository.AddUser(new User { Username = "local", HashedPassword = TestCredentials.HashPassword("local-password") });
        _repository.AddGroup(new Group { Name = "staff" });
        _external = new FakeAuthenticationProvider("ldap", r => r.Password == "directory-password"
            ? AuthResult.Success(new ExternalUser { PrimaryGroup = "staff" })
            : AuthResult.Failure("wrong password"));
        var authenticator = new UserAuthenticator([new DatabaseAuthenticationProvider(_repository), _external], _repository);
        _logins = new PasswordLoginService(_repository, new LoginBanTracker(TimeProvider.System), NullLogger<PasswordLoginService>.Instance,
            authenticator: authenticator);
    }

    private ValueTask<PasswordLoginResult> Login(string username, string password) =>
        _logins.LoginAsync("WebDAV", UserProtocols.WebDav, username, password, IPAddress.Parse("192.0.2.1"), TestContext.Current.CancellationToken);

    [Fact]
    public async Task A_directory_user_logs_in_over_webdav_and_is_created_with_its_group()
    {
        var result = await Login("dir-user", "directory-password");

        Assert.Equal(PasswordLoginStatus.Ok, result.Status);
        var stored = _repository.GetUser("dir-user");
        Assert.Equal("ldap", stored.AuthenticationProvider);
        Assert.Equal(_repository.GetGroups().Single().Id, stored.PrimaryGroupId);
        Assert.Equal("dir-user", result.User!.Username);
    }

    [Fact]
    public async Task A_wrong_directory_password_fails_and_creates_nothing()
    {
        var result = await Login("dir-user", "wrong");

        Assert.Equal(PasswordLoginStatus.Failed, result.Status);
        Assert.Equal("wrong password", result.Reason);
        Assert.Null(_repository.GetUser("dir-user"));
    }

    [Fact]
    public async Task A_disabled_directory_user_is_refused_without_asking_the_directory()
    {
        Assert.Equal(PasswordLoginStatus.Ok, (await Login("dir-user", "directory-password")).Status);
        var user = _repository.GetUser("dir-user");
        user.Status = UserStatus.Disabled;
        _repository.UpdateUser(user);
        var calls = _external.Calls.Count;

        var result = await Login("dir-user", "directory-password");

        Assert.Equal(PasswordLoginStatus.Failed, result.Status);
        Assert.Equal("the user is disabled", result.Reason);
        Assert.Equal(calls, _external.Calls.Count);
    }

    [Fact]
    public async Task A_local_user_still_logs_in_with_its_stored_password()
    {
        Assert.Equal(PasswordLoginStatus.Ok, (await Login("local", "local-password")).Status);
        Assert.Equal(PasswordLoginStatus.Failed, (await Login("local", "directory-password")).Status);
        Assert.Empty(_external.Calls);
    }
}
