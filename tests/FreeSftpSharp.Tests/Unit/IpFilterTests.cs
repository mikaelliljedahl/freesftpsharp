using System.Net;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>The connection filter (<see cref="IpFilter"/>): global blacklist, global whitelist mode and bans.</summary>
public sealed class IpFilterTests
{
    private readonly LoginBanTracker _bans = new(new FakeTimeProvider());
    private readonly IpFilter _filter = new(NullLogger.Instance);

    private IpFilterResult Check(string address, ServerSettings settings) =>
        _filter.Check(new IPEndPoint(IPAddress.Parse(address), 40000), settings, _bans);

    [Fact]
    public void Without_lists_every_address_is_allowed()
    {
        var settings = new ServerSettings();

        Assert.Equal(IpFilterResult.Allowed, Check("8.8.8.8", settings));
        Assert.Equal(IpFilterResult.Allowed, Check("2001:db8::1", settings));
    }

    [Theory]
    [InlineData("10.1.2.3", IpFilterResult.Blacklisted)]
    [InlineData("::ffff:10.1.2.3", IpFilterResult.Blacklisted)]
    [InlineData("2001:db8:1::7", IpFilterResult.Blacklisted)]
    [InlineData("11.0.0.1", IpFilterResult.Allowed)]
    [InlineData("2001:db8:2::7", IpFilterResult.Allowed)]
    public void Blacklisted_networks_are_rejected(string address, IpFilterResult expected)
    {
        var settings = new ServerSettings { BlacklistedIps = new List<string> { "10.0.0.0/8", "2001:db8:1::/48", "not-an-ip" } };

        Assert.Equal(expected, Check(address, settings));
    }

    [Theory]
    [InlineData("192.168.5.5", IpFilterResult.Allowed)]
    [InlineData("::ffff:192.168.5.5", IpFilterResult.Allowed)]
    [InlineData("192.168.6.5", IpFilterResult.NotWhitelisted)]
    [InlineData("127.0.0.1", IpFilterResult.NotWhitelisted)] // loopback is not special in whitelist mode
    public void In_whitelist_mode_only_listed_networks_are_allowed(string address, IpFilterResult expected)
    {
        var settings = new ServerSettings { OnlyWhitelistedIps = true, WhitelistedIps = new List<string> { "192.168.5.0/24" } };

        Assert.Equal(expected, Check(address, settings));
    }

    [Fact]
    public void Whitelist_mode_with_an_empty_list_allows_every_address()
    {
        // The same rule as the per-user whitelist: an empty list means "no check", so a half-done setting
        // cannot lock everybody out.
        var settings = new ServerSettings { OnlyWhitelistedIps = true, WhitelistedIps = new List<string>() };

        Assert.Equal(IpFilterResult.Allowed, Check("8.8.8.8", settings));
    }

    [Fact]
    public void The_whitelist_is_ignored_when_whitelist_mode_is_off()
    {
        var settings = new ServerSettings { OnlyWhitelistedIps = false, WhitelistedIps = new List<string> { "192.168.5.0/24" } };

        Assert.Equal(IpFilterResult.Allowed, Check("8.8.8.8", settings));
    }

    [Fact]
    public void The_blacklist_wins_over_the_whitelist()
    {
        var settings = new ServerSettings
        {
            OnlyWhitelistedIps = true,
            WhitelistedIps = new List<string> { "10.0.0.0/8" },
            BlacklistedIps = new List<string> { "10.6.6.6" },
        };

        Assert.Equal(IpFilterResult.Blacklisted, Check("10.6.6.6", settings));
        Assert.Equal(IpFilterResult.Allowed, Check("10.6.6.7", settings));
    }

    [Fact]
    public void A_banned_address_is_rejected()
    {
        var policy = new BanPolicy(1, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1), ExemptLoopback: false);
        _bans.RecordFailure(IPAddress.Parse("10.0.0.9"), policy);

        Assert.Equal(IpFilterResult.Banned, Check("::ffff:10.0.0.9", new ServerSettings()));
        Assert.Equal(IpFilterResult.Allowed, Check("10.0.0.10", new ServerSettings()));
    }

    [Fact]
    public void A_connection_without_an_IP_end_point_is_rejected()
    {
        var result = _filter.Check(new DnsEndPoint("example.com", 22), new ServerSettings(), _bans);

        Assert.Equal(IpFilterResult.Rejected, result);
    }
}
