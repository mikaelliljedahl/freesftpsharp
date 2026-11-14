using SshServer.Interfaces;
using SshServer.Interfaces.Net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

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
    /// </summary>
    public sealed class LoginBanTracker : IIpBanService
    {
        /// <summary>How often old failure records and expired bans are removed.</summary>
        private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(1);

        private readonly object _lock = new();
        private readonly Dictionary<IPAddress, Queue<DateTimeOffset>> _failures = new();
        private readonly Dictionary<IPAddress, IpBan> _bans = new();
        private DateTimeOffset _nextCleanup;

        public LoginBanTracker(TimeProvider time)
        {
            Time = time ?? throw new ArgumentNullException(nameof(time));
            _nextCleanup = time.GetUtcNow() + CleanupInterval;
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

                _bans[address] = new IpBan(address, now, now + policy.Duration, times.Count);
                _failures.Remove(address); // counted from zero after the ban
                return true;
            }
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
            lock (_lock)
            {
                var wasBanned = IsBannedCore(address, now);
                _bans.Remove(address);
                _failures.Remove(address);
                return wasBanned;
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
