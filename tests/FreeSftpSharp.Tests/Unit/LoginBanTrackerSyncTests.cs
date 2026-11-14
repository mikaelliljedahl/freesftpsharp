using System.Collections.Concurrent;
using System.Net;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>The shared bans of several nodes (#75): <see cref="LoginBanTracker.SyncAsync"/> with an <see cref="IIpBanStore"/>.</summary>
public sealed class LoginBanTrackerSyncTests
{
    private static readonly IPAddress Attacker = IPAddress.Parse("203.0.113.7");
    private static readonly BanPolicy Policy = new(MaxFailures: 1, Window: TimeSpan.FromMinutes(10), Duration: TimeSpan.FromMinutes(30), ExemptLoopback: false);

    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero));
    private readonly MemoryBanStore _store = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_new_ban_lifted_by_another_node_is_gone_after_the_next_sync()
    {
        var nodeA = new LoginBanTracker(_time, _store);
        var nodeB = new LoginBanTracker(_time, _store);
        Assert.True(nodeA.RecordFailure(Attacker, Policy));
        await nodeB.SyncAsync(Ct);
        Assert.True(nodeB.IsBanned(Attacker));

        Assert.True(nodeB.Unban(Attacker)); // at once, the clock does not move

        await nodeA.SyncAsync(Ct);
        Assert.False(nodeA.IsBanned(Attacker));
    }

    [Fact]
    public async Task A_ban_that_could_not_be_stored_holds_on_its_node()
    {
        _store.Fail = true;
        var node = new LoginBanTracker(_time, _store);
        Assert.True(node.RecordFailure(Attacker, Policy));
        _store.Fail = false;

        await node.SyncAsync(Ct);

        Assert.True(node.IsBanned(Attacker));
    }

    [Fact]
    public async Task A_ban_stored_while_a_sync_reads_is_kept()
    {
        var node = new LoginBanTracker(_time, _store);
        _store.BeforeList = () => Assert.True(node.RecordFailure(Attacker, Policy)); // stored after the read started

        await node.SyncAsync(Ct);

        Assert.True(node.IsBanned(Attacker));
        _store.BeforeList = null;
        await node.SyncAsync(Ct);
        Assert.True(node.IsBanned(Attacker)); // now from the store
    }

    private sealed class MemoryBanStore : IIpBanStore
    {
        private readonly ConcurrentDictionary<IPAddress, IpBan> _bans = new();

        public bool Fail { get; set; }

        public Action? BeforeList { get; set; }

        public Task AddAsync(IpBan ban, CancellationToken ct)
        {
            if (Fail)
                throw new InvalidOperationException("The database is down.");
            _bans[ban.Address] = ban;
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<IpBan>> ListActiveAsync(DateTimeOffset now, CancellationToken ct)
        {
            // The snapshot is taken first, like a database read; a write during the call is not in it.
            IReadOnlyList<IpBan> snapshot = _bans.Values.Where(b => b.ExpiresAt > now).ToList();
            BeforeList?.Invoke();
            return Task.FromResult(snapshot);
        }

        public Task RemoveAsync(IPAddress address, CancellationToken ct)
        {
            _bans.TryRemove(address, out _);
            return Task.CompletedTask;
        }

        public Task<int> RemoveExpiredAsync(DateTimeOffset now, CancellationToken ct) => Task.FromResult(0);
    }
}
