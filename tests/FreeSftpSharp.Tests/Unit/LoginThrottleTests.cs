using FxSshSftpServer.Security;
using Microsoft.Extensions.Time.Testing;

namespace FreeSftpSharp.Tests.Unit;

public sealed class LoginThrottleTests
{
    private readonly FakeTimeProvider _time = new();
    private readonly LoginThrottle _throttle;

    public LoginThrottleTests()
    {
        _throttle = new LoginThrottle(_time, maxFailures: 3, lockoutPeriod: TimeSpan.FromMinutes(5));
    }

    [Fact]
    public void A_client_is_locked_out_after_the_maximum_number_of_failures()
    {
        _throttle.RecordFailure("10.0.0.1");
        _throttle.RecordFailure("10.0.0.1");
        Assert.False(_throttle.IsLockedOut("10.0.0.1"));

        _throttle.RecordFailure("10.0.0.1");

        Assert.True(_throttle.IsLockedOut("10.0.0.1"));
        Assert.False(_throttle.IsLockedOut("10.0.0.2"));
    }

    [Fact]
    public void The_lockout_ends_after_the_lockout_period()
    {
        for (var i = 0; i < 3; i++)
            _throttle.RecordFailure("10.0.0.1");

        _time.Advance(TimeSpan.FromMinutes(5) - TimeSpan.FromSeconds(1));
        Assert.True(_throttle.IsLockedOut("10.0.0.1"));

        _time.Advance(TimeSpan.FromSeconds(2));
        Assert.False(_throttle.IsLockedOut("10.0.0.1"));
    }

    [Fact]
    public void Old_failures_outside_the_period_are_forgotten()
    {
        _throttle.RecordFailure("10.0.0.1");
        _throttle.RecordFailure("10.0.0.1");
        _time.Advance(TimeSpan.FromMinutes(6));
        _throttle.RecordFailure("10.0.0.1");

        Assert.False(_throttle.IsLockedOut("10.0.0.1"));
    }

    [Fact]
    public void A_successful_login_clears_the_failures()
    {
        _throttle.RecordFailure("10.0.0.1");
        _throttle.RecordFailure("10.0.0.1");
        _throttle.RecordSuccess("10.0.0.1");
        _throttle.RecordFailure("10.0.0.1");

        Assert.False(_throttle.IsLockedOut("10.0.0.1"));
    }
}
