using System.Collections.Concurrent;
using SshServer.Interfaces.TwoFactor;

namespace SshServer.TwoFactor;

/// <summary>
/// Counts the wrong codes per subject, so that a client that has the first factor cannot try many codes from many
/// addresses (the address bans of the protocols limit one address). After <c>maxFailures</c> wrong codes within the
/// lockout period the codes of the subject are refused until the period after the last failure has passed. In memory
/// and per node.
/// </summary>
internal sealed class TwoFactorAttemptLimiter
{
    private readonly TimeProvider _time;
    private readonly int _maxFailures;
    private readonly TimeSpan _period;
    private readonly ConcurrentDictionary<TwoFactorSubject, Queue<DateTimeOffset>> _failures = new();

    public TwoFactorAttemptLimiter(TimeProvider time, int maxFailures, TimeSpan period)
    {
        _time = time;
        _maxFailures = maxFailures;
        _period = period;
    }

    public bool IsLockedOut(TwoFactorSubject subject)
    {
        if (!_failures.TryGetValue(subject, out var failures))
            return false;
        lock (failures)
        {
            Prune(failures);
            return failures.Count >= _maxFailures;
        }
    }

    public void RecordFailure(TwoFactorSubject subject)
    {
        if (_failures.Count > 10_000)
            _failures.Clear(); // bound the memory; a lost entry only forgets some failures
        var failures = _failures.GetOrAdd(subject, _ => new Queue<DateTimeOffset>());
        lock (failures)
        {
            Prune(failures);
            failures.Enqueue(_time.GetUtcNow());
            while (failures.Count > _maxFailures)
                failures.Dequeue();
        }
    }

    public void RecordSuccess(TwoFactorSubject subject) => _failures.TryRemove(subject, out _);

    private void Prune(Queue<DateTimeOffset> failures)
    {
        var now = _time.GetUtcNow();
        if (failures.Count >= _maxFailures)
        {
            if (now - failures.Last() < _period)
                return;
            failures.Clear();
            return;
        }
        while (failures.Count > 0 && now - failures.Peek() >= _period)
            failures.Dequeue();
    }
}
