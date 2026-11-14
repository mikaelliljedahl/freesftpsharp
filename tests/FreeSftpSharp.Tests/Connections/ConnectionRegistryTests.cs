using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces.Connections;
using SshServerModule.Connections;

namespace FreeSftpSharp.Tests.Connections;

/// <summary>The in-memory registry of the open connections (<see cref="ConnectionRegistry"/>).</summary>
public sealed class ConnectionRegistryTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _time = new(Start);
    private readonly ConnectionRegistry _registry;
    private readonly List<ConnectionEvent> _events = new();
    private readonly List<string> _disconnectReasons = new();

    public ConnectionRegistryTests()
    {
        _registry = new ConnectionRegistry(_time);
        _registry.Changed += _events.Add;
    }

    private ConnectionInfo Register(string endPoint = "127.0.0.1:50000") =>
        _registry.Register(new ConnectionRegistration(ConnectionProtocols.Sftp, endPoint, reason =>
        {
            _disconnectReasons.Add(reason);
            return Task.CompletedTask;
        }));

    [Fact]
    public void TrySetAuthenticated_refuses_a_login_over_the_session_limit_and_counts_without_case()
    {
        var first = Register();
        var second = Register();
        var third = Register();

        Assert.True(_registry.TrySetAuthenticated(first.Id, "alice", "password", maxSessions: 2));
        Assert.True(_registry.TrySetAuthenticated(second.Id, "ALICE", "password", maxSessions: 2));
        Assert.False(_registry.TrySetAuthenticated(third.Id, "alice", "password", maxSessions: 2));

        Assert.Null(_registry.Get(third.Id)!.Username);
        Assert.Equal(2, _registry.CountSessions("Alice", third.Id));
        Assert.Equal(1, _registry.CountSessions("alice", first.Id));
        Assert.Equal(2, _events.Count(e => e.Kind == ConnectionEventKind.Authenticated));
        Assert.True(_registry.TrySetAuthenticated(third.Id, "bob", "password", maxSessions: 1));
        Assert.True(_registry.TrySetAuthenticated(Register().Id, "alice", "password", maxSessions: 0)); // 0: no limit
        Assert.False(_registry.TrySetAuthenticated(Guid.NewGuid(), "carol", "password", maxSessions: 0));
    }

    [Fact]
    public async Task Logins_at_the_same_time_never_take_more_than_the_session_limit()
    {
        var connections = Enumerable.Range(0, 50).Select(_ => Register()).ToList();
        _registry.Changed -= _events.Add; // the list is not thread safe

        var results = await Task.WhenAll(connections.Select(c => Task.Run(() => _registry.TrySetAuthenticated(c.Id, "alice", "password", maxSessions: 3))));

        Assert.Equal(3, results.Count(r => r));
        Assert.Equal(3, _registry.CountSessions("alice", Guid.Empty));
    }

    [Fact]
    public void Register_adds_an_unauthenticated_connection_and_raises_Connected()
    {
        var connection = Register("192.0.2.10:40001");

        Assert.NotEqual(Guid.Empty, connection.Id);
        Assert.Equal(ConnectionProtocols.Sftp, connection.Protocol);
        Assert.Equal("192.0.2.10:40001", connection.RemoteEndPoint);
        Assert.Equal(Start, connection.ConnectedAt);
        Assert.Equal(Start, connection.LastActivity);
        Assert.Null(connection.Username);
        Assert.Null(connection.AuthenticatedAt);
        Assert.Null(connection.ClientVersion);
        Assert.Empty(connection.Transfers);
        Assert.Equal(connection, Assert.Single(_registry.GetAll()));
        var raised = Assert.Single(_events);
        Assert.Equal(ConnectionEventKind.Connected, raised.Kind);
        Assert.Equal(connection.Id, raised.Connection.Id);
    }

    [Fact]
    public void Each_connection_gets_its_own_id_and_GetAll_lists_the_oldest_first()
    {
        var first = Register("127.0.0.1:1");
        _time.Advance(TimeSpan.FromSeconds(1));
        var second = Register("127.0.0.1:2");

        Assert.NotEqual(first.Id, second.Id);
        Assert.Equal([first.Id, second.Id], _registry.GetAll().Select(c => c.Id));
    }

    [Fact]
    public void SetAuthenticated_records_the_user_the_method_and_the_time_and_raises_Authenticated()
    {
        var connection = Register();
        _time.Advance(TimeSpan.FromSeconds(3));

        _registry.SetAuthenticated(connection.Id, "alice", "publickey");

        var info = _registry.Get(connection.Id)!;
        Assert.Equal("alice", info.Username);
        Assert.Equal("publickey", info.AuthMethod);
        Assert.Equal(Start.AddSeconds(3), info.AuthenticatedAt);
        Assert.Equal(Start.AddSeconds(3), info.LastActivity);
        Assert.Equal(ConnectionEventKind.Authenticated, _events.Last().Kind);
        Assert.Equal("alice", _events.Last().Connection.Username);
    }

    [Fact]
    public void SetClientVersion_and_RecordActivity_update_the_connection()
    {
        var connection = Register();
        _time.Advance(TimeSpan.FromMinutes(2));

        _registry.SetClientVersion(connection.Id, "SSH-2.0-OpenSSH_9.6");
        _registry.RecordActivity(connection.Id);

        var info = _registry.Get(connection.Id)!;
        Assert.Equal("SSH-2.0-OpenSSH_9.6", info.ClientVersion);
        Assert.Equal(Start.AddMinutes(2), info.LastActivity);
        Assert.Equal(Start, info.ConnectedAt);
    }

    [Fact]
    public void A_snapshot_does_not_change_after_an_update()
    {
        var connection = Register();
        var before = _registry.Get(connection.Id)!;

        _registry.SetAuthenticated(connection.Id, "alice", "password");

        Assert.Null(before.Username);
        Assert.Null(connection.Username);
    }

    [Fact]
    public void A_transfer_shows_the_growing_byte_count_until_it_is_disposed()
    {
        var connection = Register();
        _time.Advance(TimeSpan.FromSeconds(1));

        var progress = _registry.BeginTransfer(connection.Id, "/up/big.bin", TransferDirection.Upload);
        progress.AddBytes(1000);
        var first = Assert.Single(_registry.Get(connection.Id)!.Transfers);
        _time.Advance(TimeSpan.FromSeconds(1));
        progress.AddBytes(500);
        var second = Assert.Single(_registry.Get(connection.Id)!.Transfers);

        Assert.Equal("/up/big.bin", first.VirtualPath);
        Assert.Equal(TransferDirection.Upload, first.Direction);
        Assert.Equal(Start.AddSeconds(1), first.StartedAt);
        Assert.Equal(1000, first.Bytes);
        Assert.Equal(1500, second.Bytes);
        Assert.Equal(first.Id, second.Id);
        Assert.Equal(Start.AddSeconds(2), _registry.Get(connection.Id)!.LastActivity);

        progress.Dispose();

        Assert.Empty(_registry.Get(connection.Id)!.Transfers);
    }

    [Fact]
    public void Several_transfers_of_one_connection_are_listed()
    {
        var connection = Register();
        using var upload = _registry.BeginTransfer(connection.Id, "/a", TransferDirection.Upload);
        using var download = _registry.BeginTransfer(connection.Id, "/b", TransferDirection.Download);

        Assert.Equal(2, _registry.Get(connection.Id)!.Transfers.Count);
    }

    [Fact]
    public void Unregister_removes_the_connection_once_and_raises_Disconnected()
    {
        var connection = Register();
        _registry.SetAuthenticated(connection.Id, "alice", "password");

        Assert.True(_registry.Unregister(connection.Id));
        Assert.False(_registry.Unregister(connection.Id));

        Assert.Empty(_registry.GetAll());
        Assert.Null(_registry.Get(connection.Id));
        Assert.Single(_events, e => e.Kind == ConnectionEventKind.Disconnected);
        Assert.Equal("alice", _events.Last().Connection.Username);
    }

    [Fact]
    public async Task DisconnectAsync_closes_the_connection_with_the_reason_and_removes_it()
    {
        var connection = Register();
        var other = Register("127.0.0.1:2");

        Assert.True(await _registry.DisconnectAsync(connection.Id, "Maintenance."));

        Assert.Equal(["Maintenance."], _disconnectReasons);
        Assert.Equal(other.Id, Assert.Single(_registry.GetAll()).Id);
        Assert.Equal(ConnectionEventKind.Disconnected, _events.Last().Kind);
    }

    /// <summary>The entry leaves the registry at once, not when the protocol has finished its close (an SSH session waits for its send queue).</summary>
    [Fact]
    public async Task DisconnectAsync_removes_the_connection_before_the_protocol_has_closed_it()
    {
        var closing = new TaskCompletionSource();
        var connection = _registry.Register(new ConnectionRegistration(ConnectionProtocols.Sftp, "127.0.0.1:3", _ => closing.Task));

        var disconnect = _registry.DisconnectAsync(connection.Id, "Disabled.");

        Assert.False(disconnect.IsCompleted);
        Assert.Null(_registry.Get(connection.Id));
        closing.SetResult();
        Assert.True(await disconnect);
    }

    [Fact]
    public async Task DisconnectAsync_of_an_unknown_connection_returns_false()
    {
        Assert.False(await _registry.DisconnectAsync(Guid.NewGuid(), "x"));
        Assert.Empty(_disconnectReasons);
    }

    [Fact]
    public void Updates_of_an_unknown_or_removed_connection_are_ignored()
    {
        var connection = Register();
        _registry.Unregister(connection.Id);

        _registry.SetAuthenticated(connection.Id, "alice", "password");
        _registry.SetClientVersion(connection.Id, "SSH-2.0-x");
        _registry.RecordActivity(connection.Id);
        using var progress = _registry.BeginTransfer(connection.Id, "/a", TransferDirection.Download);
        progress.AddBytes(10);

        Assert.Empty(_registry.GetAll());
        Assert.DoesNotContain(_events, e => e.Kind == ConnectionEventKind.Authenticated);
    }

    [Fact]
    public void A_failing_event_handler_does_not_stop_the_registry_or_the_other_handlers()
    {
        var seen = 0;
        _registry.Changed += _ => throw new InvalidOperationException("bad subscriber");
        _registry.Changed += _ => seen++;

        var connection = Register();
        _registry.SetAuthenticated(connection.Id, "alice", "password");

        Assert.Equal(2, seen);
        Assert.Equal("alice", _registry.Get(connection.Id)!.Username);
    }
}
