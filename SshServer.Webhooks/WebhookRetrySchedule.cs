namespace SshServer.Webhooks;

/// <summary>
/// When a failed asynchronous delivery is sent again: 10 s, 1 min, 5 min, 30 min and 2 h after the failed attempts, each
/// with up to 20 % jitter added (so many deliveries that failed together do not come back at the same second). After
/// the sixth failed attempt the delivery is a dead letter.
/// </summary>
public sealed class WebhookRetrySchedule
{
    public const double JitterFraction = 0.2;

    public static IReadOnlyList<TimeSpan> Delays { get; } =
    [
        TimeSpan.FromSeconds(10),
        TimeSpan.FromMinutes(1),
        TimeSpan.FromMinutes(5),
        TimeSpan.FromMinutes(30),
        TimeSpan.FromHours(2),
    ];

    /// <summary>The attempts of a delivery: the first one and one per delay.</summary>
    public static int MaxAttempts => Delays.Count + 1;

    private readonly Func<double> _random;

    /// <param name="random">A value in [0, 1) for the jitter. Null: <see cref="Random.Shared"/>.</param>
    public WebhookRetrySchedule(Func<double>? random = null)
    {
        _random = random ?? Random.Shared.NextDouble;
    }

    /// <summary>The wait after <paramref name="failedAttempts"/> failed attempts; null: no more attempts (dead letter).</summary>
    public TimeSpan? DelayAfter(int failedAttempts)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(failedAttempts, 1);
        if (failedAttempts > Delays.Count)
            return null;
        var delay = Delays[failedAttempts - 1];
        return delay + delay * (JitterFraction * Math.Clamp(_random(), 0, 1));
    }
}
