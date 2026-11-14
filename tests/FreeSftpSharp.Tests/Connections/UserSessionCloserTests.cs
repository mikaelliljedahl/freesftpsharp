using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServerModule.Connections;

namespace FreeSftpSharp.Tests.Connections;

/// <summary><see cref="UserSessionCloser"/> (issues #61 and #132): a disabled or removed user loses its open sessions.</summary>
public sealed class UserSessionCloserTests
{
    private readonly ConnectionRegistry _registry = new(new FakeTimeProvider());
    private readonly List<(string User, string Reason)> _closed = new();
    private readonly UserSessionCloser _sink;

    public UserSessionCloserTests()
    {
        _sink = new UserSessionCloser(_registry);
    }

    private Guid Open(string username)
    {
        var connection = _registry.Register(new ConnectionRegistration(ConnectionProtocols.Sftp, "127.0.0.1:1", reason =>
        {
            _closed.Add((username, reason));
            return Task.CompletedTask;
        }));
        _registry.SetAuthenticated(connection.Id, username, "password");
        return connection.Id;
    }

    private static ProviderEvent Update(string username, UserStatus status, params string[] changed) =>
        new(ProviderAction.Update, ProviderObjectType.User, username)
        {
            Object = UserSnapshot.From(new User { Username = username, Status = status }),
            ChangedFields = changed,
        };

    [Fact]
    public async Task Disabling_a_user_closes_its_sessions_only()
    {
        Open("alice");
        Open("Alice");
        var bob = Open("bob");

        await _sink.HandleAsync(Update("alice", UserStatus.Disabled, "Status"), CancellationToken.None);

        Assert.Equal([("alice", "The account was disabled."), ("Alice", "The account was disabled.")], _closed);
        Assert.Equal([bob], _registry.GetAll().Select(c => c.Id));
    }

    [Fact]
    public async Task Other_changes_keep_the_sessions_and_removing_a_user_closes_them()
    {
        Open("alice");

        await _sink.HandleAsync(Update("alice", UserStatus.Enabled, "Status"), CancellationToken.None);
        await _sink.HandleAsync(Update("alice", UserStatus.Disabled, "MaxSessions"), CancellationToken.None);
        await _sink.HandleAsync(new AuthEvent(AuthEventType.LoginOk) { Username = "alice" }, CancellationToken.None);
        Assert.Empty(_closed);

        await _sink.HandleAsync(new ProviderEvent(ProviderAction.Delete, ProviderObjectType.User, "alice"), CancellationToken.None);
        Assert.Equal([("alice", "The account was removed.")], _closed);
    }
}
