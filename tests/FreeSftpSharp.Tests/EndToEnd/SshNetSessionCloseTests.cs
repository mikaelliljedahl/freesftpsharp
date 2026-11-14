using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Renci.SshNet;
using SshServer.Interfaces;
using SshServer.Interfaces.Events;
using SshServerModule.Connections;
using SshServerModule.Events;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>The server with the closer of the sessions and the lifecycle service that checks every 100 ms.</summary>
public sealed class SessionCloseServerFixture : SftpServerFixture
{
    private UserLifecycleService? _lifecycle;
    private ChannelEventBus? _bus;
    private UserSessionCloser? _closer;

    public RecordingEventSink Sink { get; } = new();

    protected override IEventBus? CreateEventBus()
    {
        _closer = new UserSessionCloser(Connections, () => _bus);
        _bus = new ChannelEventBus([Sink, _closer], [], NullLogger<ChannelEventBus>.Instance);
        return _bus;
    }

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        // The repository exists only now: the service reads the users from it.
        _lifecycle = new UserLifecycleService(Connections, _closer!, Repository)
        {
            Interval = TimeSpan.FromMilliseconds(100),
        };
        await _lifecycle.StartAsync(CancellationToken.None);
    }

    public override async ValueTask DisposeAsync()
    {
        if (_lifecycle is not null)
            await _lifecycle.StopAsync(CancellationToken.None);
        await base.DisposeAsync();
    }

    /// <summary>Publishes the event that the settings store publishes when an administrator changes a user.</summary>
    public ValueTask PublishUserChangedAsync(User user, params string[] changedFields) => _bus!.PublishAsync(
        new ProviderEvent(ProviderAction.Update, ProviderObjectType.User, user.Username)
        {
            Timestamp = DateTimeOffset.UtcNow,
            Object = UserSnapshot.From(user),
            ChangedFields = changedFields,
        });
}

/// <summary>
/// The end of an account while the client is connected (issue #132) with SSH.NET: the session of a user that an
/// administrator disables, and of a user that expires, is closed within a few seconds, with the reason in the events.
/// </summary>
public sealed class SshNetSessionCloseTests : IClassFixture<SessionCloseServerFixture>
{
    private readonly SessionCloseServerFixture _server;

    public SshNetSessionCloseTests(SessionCloseServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task The_session_of_a_user_that_is_disabled_is_closed()
    {
        var username = AddUser(user => { });
        using var client = _server.CreateClient(TestCredentials.Password, username);
        client.Connect();
        client.ListDirectory("/").ToList();

        var user = _server.Repository.GetUser(username);
        user.Status = UserStatus.Disabled;
        _server.Repository.UpdateUser(user);
        await _server.PublishUserChangedAsync(user, "Status");

        await AssertClosedAsync(client, username, UserSessionCloser.DisabledReason);
    }

    [Fact]
    public async Task The_session_of_a_user_that_expires_is_closed()
    {
        var username = AddUser(user => user.ExpiresAt = DateTime.UtcNow.AddSeconds(2));
        using var client = _server.CreateClient(TestCredentials.Password, username);
        client.Connect();
        client.ListDirectory("/").ToList();
        Assert.True(client.IsConnected);

        await AssertClosedAsync(client, username, UserSessionCloser.ExpiredReason);
    }

    [Fact]
    public async Task A_user_that_does_not_expire_keeps_its_session()
    {
        var username = AddUser(user => user.ExpiresAt = DateTime.UtcNow.AddDays(1));
        using var client = _server.CreateClient(TestCredentials.Password, username);
        client.Connect();

        await Task.Delay(600, TestContext.Current.CancellationToken);

        Assert.True(client.IsConnected);
        client.ListDirectory("/").ToList();
    }

    private async Task AssertClosedAsync(SftpClient client, string username, string reason)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(8);
        while (client.IsConnected && DateTime.UtcNow < deadline)
            await Task.Delay(50, TestContext.Current.CancellationToken);

        Assert.False(client.IsConnected);
        Assert.DoesNotContain(_server.Connections.GetAll(), c => c.Username == username);
        var closed = await _server.Sink.WaitForAsync<SystemEvent>(e => e.Type == SystemEventType.SessionsClosed && e.Message!.StartsWith(username + " "));
        Assert.EndsWith(": " + reason, closed[0].Message);
    }

    private string AddUser(Action<User> configure)
    {
        var username = "u" + Guid.NewGuid().ToString("N")[..12];
        var user = new User
        {
            Username = username,
            HashedPassword = TestCredentials.HashPassword(TestCredentials.Password),
            PasswordChangedAt = DateTime.UtcNow,
            UserRootDirectory = _server.UserRoot,
        };
        configure(user);
        Assert.True(_server.Repository.AddUser(user));
        return username;
    }
}
