using System.Net;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>The auto-ban of source addresses after failed logins (<see cref="LoginBanTracker"/>).</summary>
public sealed class LoginBanTrackerTests
{
    private static readonly IPAddress Attacker = IPAddress.Parse("203.0.113.7");
    private static readonly IPAddress Other = IPAddress.Parse("198.51.100.1");

    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 11, 13, 12, 0, 0, TimeSpan.Zero));
    private readonly LoginBanTracker _tracker;

    private static readonly BanPolicy Policy = new(
        MaxFailures: 3, Window: TimeSpan.FromMinutes(10), Duration: TimeSpan.FromMinutes(30), ExemptLoopback: true);

    public LoginBanTrackerTests()
    {
        _tracker = new LoginBanTracker(_time);
    }

    [Fact]
    public void An_address_is_banned_after_the_maximum_number_of_failures()
    {
        Assert.False(_tracker.RecordFailure(Attacker, Policy));
        Assert.False(_tracker.RecordFailure(Attacker, Policy));
        Assert.False(_tracker.IsBanned(Attacker));

        Assert.True(_tracker.RecordFailure(Attacker, Policy)); // this failure causes the ban

        Assert.True(_tracker.IsBanned(Attacker));
        Assert.False(_tracker.IsBanned(Other));
    }

    [Fact]
    public void Failures_outside_the_window_are_not_counted()
    {
        _tracker.RecordFailure(Attacker, Policy);
        _tracker.RecordFailure(Attacker, Policy);
        _time.Advance(TimeSpan.FromMinutes(10) + TimeSpan.FromSeconds(1));

        Assert.False(_tracker.RecordFailure(Attacker, Policy));
        Assert.False(_tracker.RecordFailure(Attacker, Policy));
        Assert.False(_tracker.IsBanned(Attacker));

        Assert.True(_tracker.RecordFailure(Attacker, Policy));
    }

    [Fact]
    public void The_window_slides()
    {
        _tracker.RecordFailure(Attacker, Policy); // t = 0
        _time.Advance(TimeSpan.FromMinutes(6));
        _tracker.RecordFailure(Attacker, Policy); // t = 6
        _time.Advance(TimeSpan.FromMinutes(6));

        // t = 12: the first failure is out of the window, so this is failure 2 of 3.
        Assert.False(_tracker.RecordFailure(Attacker, Policy));
        _time.Advance(TimeSpan.FromMinutes(1));
        Assert.True(_tracker.RecordFailure(Attacker, Policy));
    }

    [Fact]
    public void The_ban_ends_after_the_ban_duration()
    {
        BanNow(Attacker);
        var ban = Assert.Single(_tracker.GetActiveBans());
        Assert.Equal(_time.GetUtcNow() + TimeSpan.FromMinutes(30), ban.ExpiresAt);

        _time.Advance(TimeSpan.FromMinutes(30) - TimeSpan.FromSeconds(1));
        Assert.True(_tracker.IsBanned(Attacker));

        _time.Advance(TimeSpan.FromSeconds(1));
        Assert.False(_tracker.IsBanned(Attacker));
        Assert.Empty(_tracker.GetActiveBans());
    }

    [Fact]
    public void After_a_ban_the_failures_are_counted_from_zero()
    {
        BanNow(Attacker);
        _time.Advance(TimeSpan.FromMinutes(31));

        Assert.False(_tracker.RecordFailure(Attacker, Policy));
        Assert.False(_tracker.IsBanned(Attacker));
    }

    [Fact]
    public void Loopback_is_never_banned_when_it_is_exempt()
    {
        foreach (var loopback in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback, IPAddress.Parse("::ffff:127.0.0.1"), IPAddress.Parse("127.8.9.10") })
        {
            for (var i = 0; i < 10; i++)
                Assert.False(_tracker.RecordFailure(loopback, Policy));
            Assert.False(_tracker.IsBanned(loopback));
        }
    }

    [Fact]
    public void Loopback_is_banned_when_it_is_not_exempt()
    {
        var policy = Policy with { ExemptLoopback = false };

        for (var i = 0; i < 3; i++)
            _tracker.RecordFailure(IPAddress.Loopback, policy);

        Assert.True(_tracker.IsBanned(IPAddress.Loopback));
    }

    [Fact]
    public void IPv4_mapped_addresses_count_as_the_IPv4_address()
    {
        var mapped = IPAddress.Parse("::ffff:203.0.113.7");
        _tracker.RecordFailure(mapped, Policy);
        _tracker.RecordFailure(Attacker, Policy);
        _tracker.RecordFailure(mapped, Policy);

        Assert.True(_tracker.IsBanned(Attacker));
        Assert.True(_tracker.IsBanned(mapped));
        Assert.Equal(Attacker, Assert.Single(_tracker.GetActiveBans()).Address);
    }

    [Theory]
    [InlineData(0, 600, 1800)]
    [InlineData(3, 0, 1800)]
    [InlineData(3, 600, 0)]
    public void A_policy_with_a_zero_value_never_bans(int maxFailures, int windowSeconds, int durationSeconds)
    {
        var policy = new BanPolicy(maxFailures, TimeSpan.FromSeconds(windowSeconds), TimeSpan.FromSeconds(durationSeconds), ExemptLoopback: false);
        Assert.False(policy.IsEnabled);

        for (var i = 0; i < 10; i++)
            Assert.False(_tracker.RecordFailure(Attacker, policy));

        Assert.False(_tracker.IsBanned(Attacker));
    }

    [Fact]
    public void Unban_lifts_only_that_ban_and_forgets_its_failures()
    {
        BanNow(Attacker);
        BanNow(Other);

        Assert.True(_tracker.Unban(Attacker));

        Assert.False(_tracker.IsBanned(Attacker));
        Assert.True(_tracker.IsBanned(Other));
        Assert.False(_tracker.RecordFailure(Attacker, Policy)); // counted from zero again
        Assert.False(_tracker.Unban(IPAddress.Parse("192.0.2.99")));
    }

    [Fact]
    public void Unban_accepts_the_IPv4_mapped_form()
    {
        BanNow(Attacker);

        Assert.True(_tracker.Unban(IPAddress.Parse("::ffff:203.0.113.7")));
        Assert.False(_tracker.IsBanned(Attacker));
    }

    [Fact]
    public void The_failures_of_one_address_do_not_count_for_another()
    {
        _tracker.RecordFailure(Attacker, Policy);
        _tracker.RecordFailure(Attacker, Policy);

        Assert.False(_tracker.RecordFailure(Other, Policy));
        Assert.False(_tracker.IsBanned(Other));
        Assert.True(_tracker.RecordFailure(Attacker, Policy));
    }

    [Fact]
    public void GetActiveBans_lists_the_bans_with_their_times()
    {
        var bannedAt = _time.GetUtcNow();
        BanNow(Attacker);
        _time.Advance(TimeSpan.FromMinutes(1));
        BanNow(Other);

        var bans = _tracker.GetActiveBans().OrderBy(b => b.BannedAt).ToList();

        Assert.Equal(2, bans.Count);
        Assert.Equal(Attacker, bans[0].Address);
        Assert.Equal(bannedAt, bans[0].BannedAt);
        Assert.Equal(bannedAt + TimeSpan.FromMinutes(30), bans[0].ExpiresAt);
        Assert.Equal(3, bans[0].FailedAttempts);
        Assert.Equal(Other, bans[1].Address);
    }

    [Fact]
    public void The_tracker_is_an_IIpBanService()
    {
        IIpBanService service = _tracker;
        BanNow(Attacker);

        Assert.True(service.IsBanned(Attacker));
        Assert.Single(service.GetActiveBans());
        Assert.True(service.Unban(Attacker));
    }

    [Fact]
    public void Old_failure_records_are_removed()
    {
        for (var i = 0; i < 100; i++)
            _tracker.RecordFailure(IPAddress.Parse($"192.0.2.{i}"), Policy);
        Assert.Equal(100, _tracker.TrackedAddressCount);

        _time.Advance(TimeSpan.FromHours(1));
        _tracker.RecordFailure(Attacker, Policy); // triggers the clean-up

        Assert.Equal(1, _tracker.TrackedAddressCount);
    }

    [Fact]
    public void BanPolicy_is_read_from_the_settings()
    {
        var settings = new ServerSettings
        {
            MaxLoginAttemptsBeforeBan = 4,
            LoginFailureWindowSeconds = 60,
            BanDurationSeconds = 120,
            ExemptLoopbackFromBan = false,
        };

        var policy = BanPolicy.FromSettings(settings);

        Assert.Equal(new BanPolicy(4, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(120), false), policy);
        Assert.True(policy.IsEnabled);
    }

    [Fact]
    public void New_settings_have_sensible_defaults()
    {
        var settings = new ServerSettings();

        Assert.Equal(5, settings.MaxLoginAttemptsBeforeBan);
        Assert.Equal(600, settings.LoginFailureWindowSeconds);
        Assert.Equal(1800, settings.BanDurationSeconds);
        Assert.True(settings.ExemptLoopbackFromBan);
        Assert.False(settings.OnlyWhitelistedIps);
    }

    private void BanNow(IPAddress address)
    {
        for (var i = 0; i < Policy.MaxFailures; i++)
            _tracker.RecordFailure(address, Policy);
        Assert.True(_tracker.IsBanned(address));
    }
}
