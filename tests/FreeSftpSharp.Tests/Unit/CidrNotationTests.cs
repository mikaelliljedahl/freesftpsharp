using System.Net;
using SshServer.Interfaces.Net;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>The shared CIDR helper (<see cref="CidrNotation"/>) that the server and the admin UI use.</summary>
public sealed class CidrNotationTests
{
    [Theory]
    [InlineData("10.0.0.0/8", "10.0.0.0/8")]
    [InlineData(" 192.168.1.0/24 ", "192.168.1.0/24")]
    [InlineData("192.168.1.5/24", "192.168.1.0/24")] // host bits are ignored
    [InlineData("10.1.2.3", "10.1.2.3/32")] // a single address
    [InlineData("0.0.0.0/0", "0.0.0.0/0")]
    [InlineData("2001:db8::/32", "2001:db8::/32")]
    [InlineData("2001:db8::1", "2001:db8::1/128")]
    [InlineData("::1", "::1/128")]
    [InlineData("::ffff:10.0.0.0/104", "10.0.0.0/8")] // IPv4-mapped IPv6 becomes IPv4
    [InlineData("::ffff:10.1.2.3", "10.1.2.3/32")]
    public void Valid_entries_are_parsed_and_normalised(string text, string expected)
    {
        Assert.True(CidrNotation.TryParse(text, out var network));
        Assert.Equal(expected, network.ToString());
        Assert.True(CidrNotation.IsValid(text));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.0/-1")]
    [InlineData("10.0.0.0/")]
    [InlineData("10.0.0.0/8/8")]
    [InlineData("10.0.0.0/ 8")]
    [InlineData("10.0.0.0/+8")]
    [InlineData("2001:db8::/129")]
    [InlineData("256.0.0.1")]
    [InlineData("10.0.0")]
    [InlineData("example.com")]
    [InlineData("fe80::1%eth0")] // scope ids are not allowed
    [InlineData("::ffff:10.0.0.0/64")] // an IPv4-mapped network must have a prefix of 96 or more
    public void Invalid_entries_are_rejected(string? text)
    {
        Assert.False(CidrNotation.TryParse(text, out _));
        Assert.False(CidrNotation.IsValid(text));
    }

    [Fact]
    public void FindInvalid_returns_the_invalid_entries_in_order()
    {
        var invalid = CidrNotation.FindInvalid(new[] { "10.0.0.0/8", "nope", "::1", "1.2.3.4/40" });

        Assert.Equal(new[] { "nope", "1.2.3.4/40" }, invalid);
        Assert.Empty(CidrNotation.FindInvalid(null));
    }

    [Theory]
    [InlineData("192.168.1.77", true)]
    [InlineData("::ffff:192.168.1.77", true)] // a dual-stack socket gives IPv4 clients this form
    [InlineData("192.168.2.1", false)]
    [InlineData("2001:db8::5", true)]
    [InlineData("2001:db9::5", false)]
    [InlineData("10.9.9.9", true)]
    public void Contains_matches_IPv4_IPv6_and_IPv4_mapped_addresses(string address, bool expected)
    {
        var networks = CidrNotation.ParseValid(new[] { "192.168.1.0/24", "2001:db8::/32", "10.9.9.9", "garbage" });

        Assert.Equal(3, networks.Count);
        Assert.Equal(expected, CidrNotation.Contains(networks, IPAddress.Parse(address)));
    }

    [Fact]
    public void ParseValid_reports_invalid_entries()
    {
        var reported = new List<string>();

        var networks = CidrNotation.ParseValid(new[] { "10.0.0.0/8", "bad", "" }, reported.Add);

        Assert.Single(networks);
        Assert.Equal(new[] { "bad", "" }, reported);
    }

    [Fact]
    public void An_IPv4_network_does_not_contain_an_IPv6_address()
    {
        var networks = CidrNotation.ParseValid(new[] { "0.0.0.0/0" });

        Assert.True(CidrNotation.Contains(networks, IPAddress.Parse("8.8.8.8")));
        Assert.False(CidrNotation.Contains(networks, IPAddress.Parse("2001:db8::1")));
    }

    [Fact]
    public void Normalize_maps_IPv4_mapped_addresses_to_IPv4()
    {
        Assert.Equal(IPAddress.Parse("1.2.3.4"), CidrNotation.Normalize(IPAddress.Parse("::ffff:1.2.3.4")));
        Assert.Equal(IPAddress.Parse("2001:db8::1"), CidrNotation.Normalize(IPAddress.Parse("2001:db8::1")));
    }
}
