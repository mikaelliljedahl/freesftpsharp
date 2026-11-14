using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using FreeSftpSharp.Tests.Settings.Providers;
using Renci.SshNet;
using Renci.SshNet.Common;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;
using SshServer.Interfaces.Cluster;

namespace FreeSftpSharp.Tests.Cluster;

/// <summary>
/// Two server nodes in-process on one settings database (#75): SQLite always (a file), PostgreSQL and SQL Server when
/// their server is configured (<see cref="TestDatabase"/>). A user of one node logs in on the other, a ban of one node is
/// refused on the other, and each node lists and closes the connections of the other.
/// </summary>
public sealed class MultiNodeTests : IAsyncLifetime
{
    private static readonly TimeSpan Within = TimeSpan.FromSeconds(5);

    private readonly TempDirectory _directory = new();

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    public ValueTask DisposeAsync()
    {
        _directory.Dispose();
        return ValueTask.CompletedTask;
    }

    private async Task<(TestDatabase Database, TestNode A, TestNode B)> StartAsync(string provider)
    {
        var database = await TestDatabase.CreateAsync(provider);
        TestNode.PrepareDatabase(database);
        var a = await TestNode.StartAsync(database, "node-a", _directory.Path);
        var b = await TestNode.StartAsync(database, "node-b", _directory.Path);
        return (database, a, b);
    }

    private User NewUser(string username)
    {
        var root = Path.Combine(_directory.Path, username);
        Directory.CreateDirectory(root);
        return new User
        {
            Username = username,
            HashedPassword = TestCredentials.HashPassword(TestCredentials.Password),
            UserRootDirectory = root,
            WhitelistedIps = [],
            SecondaryGroupIds = [],
        };
    }

    private static SftpClient Client(TestNode node, string username, string password = TestCredentials.Password)
        => new("127.0.0.1", node.Port, username, password) { OperationTimeout = TimeSpan.FromSeconds(15) };

    private static async Task EventuallyAsync(Func<Task<bool>> condition, string what)
    {
        var deadline = DateTime.UtcNow + Within;
        while (!await condition())
        {
            if (DateTime.UtcNow > deadline)
                Assert.Fail($"Not within {Within.TotalSeconds} s: {what}.");
            await Task.Delay(100);
        }
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_user_created_on_one_node_logs_in_on_the_other(string provider)
    {
        var (database, a, b) = await StartAsync(provider);
        await using (database)
        await using (a)
        await using (b)
        {
            Assert.True(a.Repository.AddUser(NewUser("alice")));

            await EventuallyAsync(async () =>
            {
                using var client = Client(b, "alice");
                try
                {
                    await client.ConnectAsync(TestContext.Current.CancellationToken);
                    return client.IsConnected;
                }
                catch (SshAuthenticationException)
                {
                    return false;
                }
            }, "the login of the new user on node B");
        }
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task An_address_banned_on_one_node_is_refused_on_the_other(string provider)
    {
        var (database, a, b) = await StartAsync(provider);
        await using (database)
        await using (a)
        await using (b)
        {
            var settings = a.Repository.ServerSettings;
            settings.MaxLoginAttemptsBeforeBan = 2;
            settings.LoginFailureWindowSeconds = 60;
            settings.BanDurationSeconds = 600;
            settings.ExemptLoopbackFromBan = false;
            Assert.True(a.Repository.UpdateServerSettings(settings));
            Assert.True(a.Repository.AddUser(NewUser("bob")));
            Assert.False(await b.RefusesConnectionsAsync());

            for (var i = 0; i < 2; i++)
            {
                using var client = Client(a, "bob", "wrong");
                await Assert.ThrowsAsync<SshAuthenticationException>(() => client.ConnectAsync(TestContext.Current.CancellationToken));
            }
            Assert.True(await a.RefusesConnectionsAsync());

            await EventuallyAsync(b.RefusesConnectionsAsync, "the ban of node A on node B");
            Assert.Contains(b.Bans.GetActiveBans(), ban => ban.Address.ToString() == "127.0.0.1");

            // Lifted on B: A takes it too.
            Assert.True(b.Bans.Unban(System.Net.IPAddress.Loopback));
            await EventuallyAsync(async () => !await a.RefusesConnectionsAsync(), "the lifted ban on node A");
        }
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task One_node_lists_the_connections_of_the_other_and_closes_one(string provider)
    {
        var (database, a, b) = await StartAsync(provider);
        await using (database)
        await using (a)
        await using (b)
        {
            Assert.True(a.Repository.AddUser(NewUser("carol")));
            using var client = Client(b, "carol");
            await client.ConnectAsync(TestContext.Current.CancellationToken);
            var id = Assert.Single(b.LocalConnections.GetAll()).Id;

            await EventuallyAsync(() => Task.FromResult(a.Connections.Get(id) is { Username: "carol", Node: "node-b" }),
                "the connection of node B in the list of node A");
            Assert.Contains(a.Connections.GetAll(), c => c.Id == id && c.Node == "node-b");
            Assert.Empty(a.LocalConnections.GetAll());

            Assert.True(await a.Connections.DisconnectAsync(id, "Closed from node A."));

            await EventuallyAsync(() => Task.FromResult(b.LocalConnections.Get(id) == null && !client.IsConnected),
                "the connection closed on node B");
            await EventuallyAsync(() => Task.FromResult(a.Connections.Get(id) == null), "the closed connection gone from node A");
        }
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_change_on_one_node_tells_the_caches_of_the_other(string provider)
    {
        var (database, a, b) = await StartAsync(provider);
        await using (database)
        await using (a)
        await using (b)
        {
            var changed = new TaskCompletionSource();
            b.Services.GetRequiredService<ISettingsChangeNotifier>().Changed += () => changed.TrySetResult();
            await Task.Delay(TimeSpan.FromSeconds(1.5), TestContext.Current.CancellationToken); // B has read the version once

            Assert.True(a.Repository.AddUser(NewUser("dave")));

            await changed.Task.WaitAsync(Within, TestContext.Current.CancellationToken);
        }
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_session_limit_of_a_user_counts_the_sessions_on_every_node(string provider)
    {
        var (database, a, b) = await StartAsync(provider);
        await using (database)
        await using (a)
        await using (b)
        {
            var user = NewUser("erin");
            user.MaxSessions = 1;
            Assert.True(a.Repository.AddUser(user));
            using var first = Client(b, "erin");
            await first.ConnectAsync(TestContext.Current.CancellationToken);
            var id = Assert.Single(b.LocalConnections.GetAll()).Id;
            await EventuallyAsync(() => Task.FromResult(a.Connections.Get(id) is { Username: "erin" }), "the session of node B on node A");
            Assert.Equal(1, a.LocalConnections.CountSessions("ERIN", Guid.Empty));

            using (var second = Client(a, "erin"))
                await Assert.ThrowsAsync<SshAuthenticationException>(() => second.ConnectAsync(TestContext.Current.CancellationToken));

            first.Disconnect();
            await EventuallyAsync(async () =>
            {
                using var again = Client(a, "erin");
                try
                {
                    await again.ConnectAsync(TestContext.Current.CancellationToken);
                    return again.IsConnected;
                }
                catch (SshAuthenticationException)
                {
                    return false;
                }
            }, "a login on node A after the session on node B ended");
        }
    }
}
