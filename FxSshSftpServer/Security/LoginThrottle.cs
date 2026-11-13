using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace FxSshSftpServer.Security
{
    /// <summary>
    /// Counts failed admin logins per client (remote IP). After <c>maxFailures</c> failures inside the lockout
    /// period the client is locked out until the period after its last failure has passed. In memory only.
    /// </summary>
    public sealed class LoginThrottle
    {
        private readonly TimeProvider _time;
        private readonly int _maxFailures;
        private readonly TimeSpan _lockoutPeriod;
        private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _failures = new(StringComparer.Ordinal);

        public LoginThrottle(TimeProvider time, int maxFailures, TimeSpan lockoutPeriod)
        {
            if (maxFailures < 1)
                throw new ArgumentOutOfRangeException(nameof(maxFailures));
            _time = time;
            _maxFailures = maxFailures;
            _lockoutPeriod = lockoutPeriod;
        }

        public bool IsLockedOut(string client)
        {
            if (!_failures.TryGetValue(Key(client), out var failures))
                return false;
            lock (failures)
            {
                Prune(failures);
                return failures.Count >= _maxFailures;
            }
        }

        public void RecordFailure(string client)
        {
            // Bound the memory use if many clients fail; a lost entry only forgets some failures.
            if (_failures.Count > 10_000)
                _failures.Clear();

            var failures = _failures.GetOrAdd(Key(client), _ => new Queue<DateTimeOffset>());
            lock (failures)
            {
                Prune(failures);
                failures.Enqueue(_time.GetUtcNow());
                while (failures.Count > _maxFailures)
                    failures.Dequeue();
            }
        }

        public void RecordSuccess(string client) => _failures.TryRemove(Key(client), out _);

        private void Prune(Queue<DateTimeOffset> failures)
        {
            var now = _time.GetUtcNow();
            // Locked out: keep everything until the period after the last failure has passed.
            if (failures.Count >= _maxFailures)
            {
                var last = default(DateTimeOffset);
                foreach (var f in failures)
                    last = f;
                if (now - last < _lockoutPeriod)
                    return;
                failures.Clear();
                return;
            }

            while (failures.Count > 0 && now - failures.Peek() >= _lockoutPeriod)
                failures.Dequeue();
        }

        private static string Key(string client) => string.IsNullOrEmpty(client) ? "(unknown)" : client;
    }
}
