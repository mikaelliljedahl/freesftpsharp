using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServerModule.Connections;
using SshServerModule.Events;

namespace FreeSftpSharp.Tests.Connections;

/// <summary><see cref="UserLifecycleService"/> (issue #132): a user that expires loses its open sessions, on a fake clock.</summary>
public sealed class UserLifecycleServiceTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Start = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _time = new(Start);
    private readonly ConnectionRegistry _registry;
    private readonly InMemorySettingsRepository _repository = new(new ServerSettings());
    private readonly RecordingEventSink _events = new();
    private readonly ChannelEventBus _bus;
    private readonly UserLifecycleService _service;
    private readonly List<(string Protocol, string Reason)> _closed = new();

    public UserLifecycleServiceTests()
    {
        _registry = new ConnectionRegistry(_time);
        _bus = new ChannelEventBus([_events], [], NullLogger<ChannelEventBus>.Instance);
        var closer = new UserSessionCloser(_registry, () => _bus, _time);
        _service = new UserLifecycleService(_registry, closer, _repository, _time) { Interval = TimeSpan.FromSeconds(5) };
    }

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    public async ValueTask DisposeAsync() => await _bus.DisposeAsync();

    private void Open(string username, string protocol = ConnectionProtocols.Sftp)
    {
        var connection = _registry.Register(new ConnectionRegistration(protocol, "127.0.0.1:1", reason =>
        {
            _closed.Add((protocol, reason));
            return Task.CompletedTask;
        }));
        _registry.SetAuthenticated(connection.Id, username, "password");
    }

    private void AddUser(string username, DateTime? expiresAt = null, UserStatus status = UserStatus.Enabled)
        => Assert.True(_repository.AddUser(new User { Username = username, ExpiresAt = expiresAt, Status = status }));

    [Fact]
    public async Task A_user_that_expires_loses_its_sessions_in_every_protocol_and_the_others_keep_theirs()
    {
        AddUser("alice", Start.UtcDateTime.AddMinutes(1));
        AddUser("bob", Start.UtcDateTime.AddDays(1));
        AddUser("carol");
        Open("alice", ConnectionProtocols.Sftp);
        Open("Alice", ConnectionProtocols.WebDav);
        Open("bob");
        Open("carol");

        Assert.Equal(0, await _service.CheckAsync(TestContext.Current.CancellationToken));
        Assert.Empty(_closed);

        _time.Advance(TimeSpan.FromMinutes(1)); // the expiry is reached
        Assert.Equal(2, await _service.CheckAsync(TestContext.Current.CancellationToken));

        Assert.Equal([(ConnectionProtocols.Sftp, UserSessionCloser.ExpiredReason), (ConnectionProtocols.WebDav, UserSessionCloser.ExpiredReason)], _closed);
        Assert.Equal(["bob", "carol"], _registry.GetAll().Select(c => c.Username));
        Assert.Equal(0, await _service.CheckAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task The_close_is_in_the_event_stream_with_the_reason()
    {
        AddUser("alice", Start.UtcDateTime.AddSeconds(-1));
        Open("alice");

        await _service.CheckAsync(TestContext.Current.CancellationToken);

        var published = await _events.WaitForAsync<SystemEvent>(e => e.Type == SystemEventType.SessionsClosed);
        Assert.Equal("alice from 127.0.0.1:1: The account expired.", published[0].Message);
        Assert.Equal(ConnectionProtocols.Sftp, published[0].Source);
        Assert.Equal(Start, published[0].Timestamp);
    }

    [Fact]
    public async Task A_disabled_user_is_closed_too_even_without_an_event_and_a_user_that_is_not_stored_is_left_alone()
    {
        AddUser("alice", status: UserStatus.Disabled);
        Open("alice");
        Open("external");

        Assert.Equal(1, await _service.CheckAsync(TestContext.Current.CancellationToken));

        Assert.Equal([(ConnectionProtocols.Sftp, UserSessionCloser.DisabledReason)], _closed);
        Assert.Equal(["external"], _registry.GetAll().Select(c => c.Username));
    }

    [Fact]
    public async Task The_service_checks_every_interval_on_the_clock()
    {
        AddUser("alice", Start.UtcDateTime.AddSeconds(7));
        Open("alice");
        await _service.StartAsync(CancellationToken.None);
        try
        {
            _time.Advance(TimeSpan.FromSeconds(5)); // 5 s: not yet
            await Task.Delay(100, TestContext.Current.CancellationToken);
            Assert.Empty(_closed);

            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
            while (_closed.Count == 0 && DateTime.UtcNow < deadline)
            {
                _time.Advance(TimeSpan.FromSeconds(5));
                await Task.Delay(20, TestContext.Current.CancellationToken);
            }
            Assert.Equal([(ConnectionProtocols.Sftp, UserSessionCloser.ExpiredReason)], _closed);
        }
        finally
        {
            await _service.StopAsync(CancellationToken.None);
        }
    }
}
