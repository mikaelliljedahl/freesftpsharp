using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Interfaces;
using SshServer.Interfaces.Net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace FxSsh.SshServerModule.Security
{
    /// <summary>The auto-ban rule, read from <see cref="ServerSettings"/> for each failed login.</summary>
    /// <param name="MaxFailures">Failed logins within <paramref name="Window"/> that cause a ban.</param>
    /// <param name="Window">The sliding window in which failures are counted.</param>
    /// <param name="Duration">How long a ban lasts.</param>
    /// <param name="ExemptLoopback">Never ban loopback addresses.</param>
    public readonly record struct BanPolicy(int MaxFailures, TimeSpan Window, TimeSpan Duration, bool ExemptLoopback)
    {
        /// <summary>False when one of the values is 0 (or negative): then nothing is banned.</summary>
        public bool IsEnabled => MaxFailures > 0 && Window > TimeSpan.Zero && Duration > TimeSpan.Zero;

        public static BanPolicy FromSettings(ServerSettings settings) => new(
            settings.MaxLoginAttemptsBeforeBan,
            TimeSpan.FromSeconds(Math.Max(0, settings.LoginFailureWindowSeconds)),
            TimeSpan.FromSeconds(Math.Max(0, settings.BanDurationSeconds)),
            settings.ExemptLoopbackFromBan);
    }

    /// <summary>
    /// Counts failed logins per source address in a sliding window and bans an address after too many failures.
    /// The state is in memory only. IPv4-mapped IPv6 addresses count as the IPv4 address. A successful login does
    /// not reset any counter (otherwise one valid account would let an attacker guess the passwords of others).
    /// Thread-safe.
    /// <para>
    /// With an <see cref="IIpBanStore"/> (several nodes, <c>Cluster:Enabled</c>, issue #75) a new ban and a lifted ban are
    /// also written to the store, and <see cref="SyncAsync"/> (every poll interval) takes the bans of the other nodes. The
    /// check of an address stays in memory. The failed logins are counted per node.
    /// </para>
    /// </summary>
    public sealed class LoginBanTracker : IIpBanService
    {
        /// <summary>How often old failure records and expired bans are removed.</summary>
        private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(1);

        private readonly object _lock = new();
        private readonly Dictionary<IPAddress, Queue<DateTimeOffset>> _failures = new();
        private readonly Dictionary<IPAddress, IpBan> _bans = new();
        private DateTimeOffset _nextCleanup;
        private readonly IIpBanStore _store;
        private readonly ILogger _logger;

        /// <summary>
        /// The bans of this node that a sync must keep although the store did not have them when it read: 0 while the write
        /// is open or after it failed (the ban holds on this node only), else the <see cref="_storeWrites"/> number of the
        /// write. A sync that started after that write takes the ban from the store and drops the entry.
        /// </summary>
        private readonly Dictionary<IPAddress, long> _ownBans = new();
        private long _storeWrites;

        /// <summary>How long a write to the shared store may take before the ban stays on this node only.</summary>
        private static readonly TimeSpan StoreTimeout = TimeSpan.FromSeconds(5);

        public LoginBanTracker(TimeProvider time, IIpBanStore store = null, ILogger<LoginBanTracker> logger = null)
        {
            Time = time ?? throw new ArgumentNullException(nameof(time));
            _nextCleanup = time.GetUtcNow() + CleanupInterval;
            _store = store;
            _logger = (ILogger)logger ?? NullLogger.Instance;
        }

        /// <summary>The clock of the tracker. The server also uses it for <c>User.LastLoginAt</c>.</summary>
        public TimeProvider Time { get; }

        /// <summary>The number of addresses with failure records (for tests).</summary>
        internal int TrackedAddressCount
        {
            get { lock (_lock) return _failures.Count; }
        }

        /// <summary>
        /// Records a failed login from <paramref name="address"/>. Returns true when this failure caused a new ban.
        /// Does nothing when the policy is off, or for loopback when it is exempt.
        /// </summary>
        public bool RecordFailure(IPAddress address, BanPolicy policy)
        {
            ArgumentNullException.ThrowIfNull(address);
            if (!policy.IsEnabled)
                return false;

            address = CidrNotation.Normalize(address);
            if (policy.ExemptLoopback && IPAddress.IsLoopback(address))
                return false;

            var now = Time.GetUtcNow();
            IpBan ban;
            lock (_lock)
            {
                CleanupIfDue(now, policy.Window);

                if (IsBannedCore(address, now))
                    return false;

                if (!_failures.TryGetValue(address, out var times))
                    _failures[address] = times = new Queue<DateTimeOffset>();

                RemoveOld(times, now, policy.Window);
                times.Enqueue(now);
                if (times.Count < policy.MaxFailures)
                    return false;

                ban = new IpBan(address, now, now + policy.Duration, times.Count);
                _bans[address] = ban;
                _failures.Remove(address); // counted from zero after the ban
                if (_store != null)
                    _ownBans[address] = 0;
            }
            if (WriteToStore(ct => _store.AddAsync(ban, ct), "store the ban of", address))
            {
                lock (_lock)
                {
                    if (_ownBans.ContainsKey(address))
                        _ownBans[address] = ++_storeWrites;
                }
            }
            return true;
        }

        public bool IsBanned(IPAddress address)
        {
            ArgumentNullException.ThrowIfNull(address);
            address = CidrNotation.Normalize(address);
            var now = Time.GetUtcNow();
            lock (_lock)
                return IsBannedCore(address, now);
        }

        public IReadOnlyList<IpBan> GetActiveBans()
        {
            var now = Time.GetUtcNow();
            lock (_lock)
                return _bans.Values.Where(b => b.ExpiresAt > now).OrderBy(b => b.BannedAt).ToList();
        }

        public bool Unban(IPAddress address)
        {
            ArgumentNullException.ThrowIfNull(address);
            address = CidrNotation.Normalize(address);
            var now = Time.GetUtcNow();
            bool wasBanned;
            lock (_lock)
            {
                wasBanned = IsBannedCore(address, now);
                _bans.Remove(address);
                _failures.Remove(address);
                _ownBans.Remove(address);
            }
            WriteToStore(ct => _store.RemoveAsync(address, ct), "lift the stored ban of", address);
            return wasBanned;
        }

        /// <summary>
        /// Takes the bans of the shared store (the bans of every node) in place of the bans in memory, and removes the
        /// expired bans from the store, so a ban lifted on another node is lifted here at the next sync. A ban of this node
        /// that the read may not contain (its write is open, failed, or ended after the read started) is kept. Nothing
        /// without a store.
        /// </summary>
        public async Task SyncAsync(CancellationToken ct)
        {
            if (_store == null)
                return;
            long writesBefore;
            lock (_lock)
                writesBefore = _storeWrites;
            var start = Time.GetUtcNow();
            await _store.RemoveExpiredAsync(start, ct);
            var active = await _store.ListActiveAsync(start, ct);
            lock (_lock)
            {
                var keep = new List<IpBan>();
                foreach (var (address, write) in _ownBans.ToList())
                {
                    if (write != 0 && write <= writesBefore)
                        _ownBans.Remove(address); // stored before the read: the store decides now
                    else if (_bans.TryGetValue(address, out var own))
                        keep.Add(own);
                    else
                        _ownBans.Remove(address);
                }
                _bans.Clear();
                foreach (var ban in active)
                    _bans[CidrNotation.Normalize(ban.Address)] = ban with { Address = CidrNotation.Normalize(ban.Address) };
                foreach (var ban in keep)
                    _bans.TryAdd(ban.Address, ban);
            }
        }

        /// <summary>
        /// Writes a change to the shared store and waits for it (bans are rare; the other nodes see it at their next sync).
        /// A failure is logged: the ban then holds on this node only.
        /// </summary>
        private bool WriteToStore(Func<CancellationToken, Task> write, string what, IPAddress address)
        {
            if (_store == null)
                return false;
            try
            {
                using var timeout = new CancellationTokenSource(StoreTimeout);
                Task.Run(() => write(timeout.Token), timeout.Token).GetAwaiter().GetResult();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Could not {What} {Address} in the settings database; it holds on this node only.", what, address);
                return false;
            }
        }

        private bool IsBannedCore(IPAddress address, DateTimeOffset now)
        {
            if (!_bans.TryGetValue(address, out var ban))
                return false;
            if (ban.ExpiresAt > now)
                return true;
            _bans.Remove(address);
            return false;
        }

        private static void RemoveOld(Queue<DateTimeOffset> times, DateTimeOffset now, TimeSpan window)
        {
            while (times.Count > 0 && now - times.Peek() >= window)
                times.Dequeue();
        }

        /// <summary>Keeps memory bounded: an attacker with many addresses leaves no records after the window.</summary>
        private void CleanupIfDue(DateTimeOffset now, TimeSpan window)
        {
            if (now < _nextCleanup)
                return;
            _nextCleanup = now + CleanupInterval;

            foreach (var (address, times) in _failures.ToList())
            {
                RemoveOld(times, now, window);
                if (times.Count == 0)
                    _failures.Remove(address);
            }
            foreach (var expired in _bans.Values.Where(b => b.ExpiresAt <= now).ToList())
                _bans.Remove(expired.Address);
        }
    }
}
