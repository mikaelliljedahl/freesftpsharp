using SshServer.Webhooks;

namespace FreeSftpSharp.Tests.Webhooks;

/// <summary>The backoff: 10 s, 1 min, 5 min, 30 min, 2 h with up to 20 % jitter, then a dead letter.</summary>
public sealed class WebhookRetryScheduleTests
{
    [Fact]
    public void Without_jitter_the_delays_are_10s_1min_5min_30min_2h_and_then_none()
    {
        var schedule = new WebhookRetrySchedule(() => 0);

        Assert.Equal(TimeSpan.FromSeconds(10), schedule.DelayAfter(1));
        Assert.Equal(TimeSpan.FromMinutes(1), schedule.DelayAfter(2));
        Assert.Equal(TimeSpan.FromMinutes(5), schedule.DelayAfter(3));
        Assert.Equal(TimeSpan.FromMinutes(30), schedule.DelayAfter(4));
        Assert.Equal(TimeSpan.FromHours(2), schedule.DelayAfter(5));
        Assert.Null(schedule.DelayAfter(6));
        Assert.Equal(6, WebhookRetrySchedule.MaxAttempts);
    }

    [Fact]
    public void The_jitter_adds_at_most_20_percent_and_the_delays_always_grow()
    {
        var high = new WebhookRetrySchedule(() => 0.999999);
        var low = new WebhookRetrySchedule(() => 0);

        for (var attempt = 1; attempt <= 5; attempt++)
        {
            var max = high.DelayAfter(attempt)!.Value;
            var min = low.DelayAfter(attempt)!.Value;
            Assert.InRange(max, min, min * 1.2);
            if (attempt < 5)
                Assert.True(low.DelayAfter(attempt + 1) > max, $"The delay after {attempt + 1} attempts must be longer than after {attempt}.");
        }
    }

    [Fact]
    public void The_shared_random_jitter_stays_in_range()
    {
        var schedule = new WebhookRetrySchedule();
        for (var i = 0; i < 100; i++)
            Assert.InRange(schedule.DelayAfter(1)!.Value, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(12));
    }
}
