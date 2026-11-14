using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Renci.SshNet;
using Renci.SshNet.Common;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Permissions;
using SshServerModule.Events;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>The server with the real event bus and a recording sink, for the reasons of the refused logins.</summary>
public sealed class LifecycleServerFixture : SftpServerFixture
{
    public RecordingEventSink Sink { get; } = new();

    protected override IEventBus CreateEventBus() => new ChannelEventBus([Sink], [], NullLogger<ChannelEventBus>.Instance);

    protected override void ConfigureSettings(ServerSettings settings) => settings.PasswordMaxAgeDays = 90;
}

/// <summary>
/// The user lifecycle (issue #61) with SSH.NET: a disabled or expired user cannot log in with the right password or key,
/// the session limit refuses the third session while the first two keep working, an old password is refused while the
/// key still works, and the permissions of the primary group apply to a user without its own.
/// </summary>
public sealed class SshNetUserLifecycleTests : IClassFixture<LifecycleServerFixture>
{
    private readonly LifecycleServerFixture _server;

    public SshNetUserLifecycleTests(LifecycleServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task A_disabled_user_cannot_log_in_with_the_right_password_or_key()
    {
        var key = TestUserKeys.Ed25519();
        var username = AddUser(key, user => user.Status = UserStatus.Disabled);

        using (var client = PasswordClient(username))
            Assert.Throws<SshAuthenticationException>(() => client.Connect());
        using (var client = KeyClient(username, key))
            Assert.Throws<SshAuthenticationException>(() => client.Connect());

        var failed = await _server.Sink.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.LoginFailed && e.Username == username && e.Method == "password");
        Assert.Equal("the user is disabled", failed[0].Reason);

        // Enabled again: the same credentials work.
        var user = _server.Repository.GetUser(username);
        user.Status = UserStatus.Enabled;
        _server.Repository.UpdateUser(user);
        using (var client = PasswordClient(username))
        {
            client.Connect();
            Assert.True(client.IsConnected);
        }
    }

    [Fact]
    public async Task An_expired_user_cannot_log_in_with_the_right_password_or_key()
    {
        var key = TestUserKeys.Ed25519();
        var username = AddUser(key, user => user.ExpiresAt = DateTime.UtcNow.AddMinutes(-1));

        using (var client = PasswordClient(username))
            Assert.Throws<SshAuthenticationException>(() => client.Connect());
        using (var client = KeyClient(username, key))
            Assert.Throws<SshAuthenticationException>(() => client.Connect());

        var failed = await _server.Sink.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.LoginFailed && e.Username == username && e.Method == "publickey");
        Assert.StartsWith("the user expired at ", failed[0].Reason);
    }

    [Fact]
    public void A_user_that_expires_later_can_log_in()
    {
        var username = AddUser(null, user => user.ExpiresAt = DateTime.UtcNow.AddDays(1));

        using var client = PasswordClient(username);
        client.Connect();

        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task The_third_session_of_a_user_with_two_sessions_is_refused_and_the_first_two_keep_working()
    {
        var username = AddUser(null, user => user.MaxSessions = 2);
        var directory = _server.CreateUniqueDirectory("sessions");

        using var first = PasswordClient(username);
        first.Connect();
        using var second = PasswordClient(username);
        second.Connect();

        using (var third = PasswordClient(username))
            Assert.Throws<SshAuthenticationException>(() => third.Connect());

        first.WriteAllText(directory + "/first.txt", "1");
        second.WriteAllText(directory + "/second.txt", "2");
        Assert.Equal("1", second.ReadAllText(directory + "/first.txt"));
        var failed = await _server.Sink.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.LoginFailed && e.Username == username);
        Assert.Equal("the user has the maximum of 2 session(s) open", failed[0].Reason);

        // A closed session frees its place.
        first.Disconnect();
        Assert.True(await WaitUntilAsync(() => _server.Connections.CountSessions(username, Guid.Empty) == 1));
        using var again = PasswordClient(username);
        again.Connect();
        Assert.True(again.IsConnected);
        Assert.True(second.IsConnected);
    }

    [Fact]
    public async Task An_old_password_is_refused_and_the_key_still_works()
    {
        var key = TestUserKeys.Ed25519();
        var username = AddUser(key, user => user.PasswordChangedAt = DateTime.UtcNow.AddDays(-91));

        using (var client = PasswordClient(username))
            Assert.Throws<SshAuthenticationException>(() => client.Connect());
        using (var client = KeyClient(username, key))
        {
            client.Connect();
            Assert.True(client.IsConnected);
        }

        var failed = await _server.Sink.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.LoginFailed && e.Username == username);
        Assert.Equal("the password is older than 90 days", failed[0].Reason);
    }

    [Fact]
    public void A_user_without_own_permissions_has_those_of_its_primary_group_and_loses_them_when_it_leaves()
    {
        var group = new Group { Name = "readers-" + Guid.NewGuid().ToString("N")[..8], Permissions = new() { ["/"] = FilePermissions.List | FilePermissions.Download } };
        Assert.True(_server.Repository.AddGroup(group));
        var username = AddUser(null, user => user.PrimaryGroupId = group.Id);
        var directory = _server.CreateUniqueDirectory("group");
        File.WriteAllText(_server.PhysicalPath(directory + "/read.txt"), "read");

        using (var client = PasswordClient(username))
        {
            client.Connect();
            Assert.Equal("read", client.ReadAllText(directory + "/read.txt"));
            Assert.Throws<SftpPermissionDeniedException>(() => client.WriteAllText(directory + "/new.txt", "x"));
        }

        var user = _server.Repository.GetUser(username);
        user.PrimaryGroupId = null;
        _server.Repository.UpdateUser(user);

        using (var client = PasswordClient(username))
        {
            client.Connect();
            client.WriteAllText(directory + "/new.txt", "x");
        }
        Assert.True(File.Exists(_server.PhysicalPath(directory + "/new.txt")));
    }

    [Fact]
    public void The_allowed_networks_of_a_group_refuse_a_member_from_another_network()
    {
        var group = new Group { Name = "lan-" + Guid.NewGuid().ToString("N")[..8], AllowedIps = ["10.0.0.0/8"] };
        Assert.True(_server.Repository.AddGroup(group));
        var username = AddUser(null, user => user.SecondaryGroupIds = [group.Id]);

        using var client = PasswordClient(username);

        Assert.Throws<SshAuthenticationException>(() => client.Connect());
    }

    private string AddUser(TestUserKey? key, Action<User> configure)
    {
        var username = "u" + Guid.NewGuid().ToString("N")[..12];
        var user = new User
        {
            Username = username,
            HashedPassword = TestCredentials.HashPassword(TestCredentials.Password),
            PasswordChangedAt = DateTime.UtcNow,
            PublicKeys = key is null ? null : [key.Entry],
            AllowedAuthMethods = AuthMethods.All,
            UserRootDirectory = _server.UserRoot,
        };
        configure(user);
        Assert.True(_server.Repository.AddUser(user));
        return username;
    }

    private SftpClient PasswordClient(string username) => _server.CreateClient(TestCredentials.Password, username);

    private SftpClient KeyClient(string username, TestUserKey key)
    {
        var client = new SftpClient(SftpServerFixture.Host, _server.Port, username, key.ToPrivateKeyFile());
        client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(15);
        return client;
    }

    private static async Task<bool> WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
                return true;
            await Task.Delay(20, TestContext.Current.CancellationToken);
        }
        return condition();
    }
}
