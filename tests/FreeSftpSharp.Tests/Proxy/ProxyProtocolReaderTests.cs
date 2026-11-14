using System.Net;
using System.Text;
using SshServerModule.Proxy;

namespace FreeSftpSharp.Tests.Proxy;

/// <summary>
/// The PROXY protocol header (HAProxy, versions 1 and 2) in front of an SSH connection (#75). Security code: a header
/// that is not exactly valid is refused, and the reader never takes a byte after the header (the SSH identification).
/// </summary>
public sealed class ProxyProtocolReaderTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly byte[] V2Signature = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

    private static readonly byte[] SshIdentification = Encoding.ASCII.GetBytes("SSH-2.0-OpenSSH_9.6\r\n");

    private static async Task<(ProxyHeader Header, byte[] Remaining)> ReadAsync(byte[] header)
    {
        using var stream = new MemoryStream([.. header, .. SshIdentification]);
        var result = await ProxyProtocolReader.ReadAsync(stream, Ct);
        return (result, stream.ToArray()[(int)stream.Position..]);
    }

    private static Task<ProxyProtocolException> RefusedAsync(byte[] header)
        => Assert.ThrowsAsync<ProxyProtocolException>(async () =>
        {
            using var stream = new MemoryStream(header);
            await ProxyProtocolReader.ReadAsync(stream, Ct);
        });

    private static byte[] V1(string line) => Encoding.ASCII.GetBytes(line);

    private static byte[] V2(byte versionCommand, byte family, byte[] addresses, int? declaredLength = null)
    {
        var length = declaredLength ?? addresses.Length;
        return [.. V2Signature, versionCommand, family, (byte)(length >> 8), (byte)length, .. addresses];
    }

    private static byte[] Inet4(string source, int sourcePort, string destination, int destinationPort) =>
    [
        .. IPAddress.Parse(source).GetAddressBytes(), .. IPAddress.Parse(destination).GetAddressBytes(),
        (byte)(sourcePort >> 8), (byte)sourcePort, (byte)(destinationPort >> 8), (byte)destinationPort,
    ];

    [Fact]
    public async Task A_v1_TCP4_header_gives_the_client_address_and_leaves_the_SSH_bytes()
    {
        var (header, rest) = await ReadAsync(V1("PROXY TCP4 203.0.113.7 192.0.2.1 50123 22\r\n"));

        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.7"), 50123), header.Source);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 22), header.Destination);
        Assert.Equal(SshIdentification, rest);
    }

    [Fact]
    public async Task A_v1_TCP6_header_gives_the_client_address()
    {
        var (header, _) = await ReadAsync(V1("PROXY TCP6 2001:db8::7 2001:db8::1 50123 22\r\n"));

        Assert.Equal(new IPEndPoint(IPAddress.Parse("2001:db8::7"), 50123), header.Source);
    }

    [Fact]
    public async Task A_v1_UNKNOWN_header_keeps_the_address_of_the_connection()
    {
        var (header, rest) = await ReadAsync(V1("PROXY UNKNOWN\r\n"));

        Assert.Null(header.Source);
        Assert.Equal(SshIdentification, rest);
        Assert.Null((await ReadAsync(V1("PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n"))).Header.Source);
    }

    [Theory]
    [InlineData("PROXY TCP4 203.0.113.7 192.0.2.1 50123 22\n")] // no CR
    [InlineData("PROXY TCP4 203.0.113.7 192.0.2.1 50123\r\n")] // a field is missing
    [InlineData("PROXY TCP4 203.0.113.7 192.0.2.1 50123 22 9\r\n")] // one field too many
    [InlineData("PROXY TCP4  203.0.113.7 192.0.2.1 50123 22\r\n")] // two spaces
    [InlineData("PROXY TCP4 203.0.113 192.0.2.1 50123 22\r\n")] // not four parts
    [InlineData("PROXY TCP4 203.0.113.256 192.0.2.1 50123 22\r\n")]
    [InlineData("PROXY TCP4 2001:db8::7 192.0.2.1 50123 22\r\n")] // IPv6 in TCP4
    [InlineData("PROXY TCP6 203.0.113.7 2001:db8::1 50123 22\r\n")] // IPv4 in TCP6
    [InlineData("PROXY TCP4 203.0.113.7 192.0.2.1 65536 22\r\n")]
    [InlineData("PROXY TCP4 203.0.113.7 192.0.2.1 -1 22\r\n")]
    [InlineData("PROXY TCP4 203.0.113.7 192.0.2.1 +80 22\r\n")]
    [InlineData("PROXY UDP4 203.0.113.7 192.0.2.1 50123 22\r\n")]
    [InlineData("proxy TCP4 203.0.113.7 192.0.2.1 50123 22\r\n")]
    [InlineData("PROXY\r\n")]
    public async Task A_malformed_v1_header_is_refused(string line)
    {
        await RefusedAsync(V1(line));
    }

    [Fact]
    public async Task A_v1_header_longer_than_107_bytes_is_refused_without_reading_further()
    {
        var line = "PROXY UNKNOWN " + new string('a', 200) + "\r\n";

        await RefusedAsync(V1(line));
    }

    [Fact]
    public async Task A_connection_without_a_header_is_refused()
    {
        await RefusedAsync(SshIdentification);
        await RefusedAsync([]);
        await RefusedAsync(V1("PROXY TCP4 203.0")); // ends inside the header
    }

    [Fact]
    public async Task A_v2_PROXY_header_over_IPv4_gives_the_client_address_and_skips_the_TLVs()
    {
        byte[] tlv = [0x04, 0x00, 0x02, 0xAB, 0xCD]; // PP2_TYPE_NOOP with two bytes
        var (header, rest) = await ReadAsync(V2(0x21, 0x11, [.. Inet4("203.0.113.7", 50123, "192.0.2.1", 22), .. tlv]));

        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.7"), 50123), header.Source);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 22), header.Destination);
        Assert.Equal(SshIdentification, rest);
    }

    [Fact]
    public async Task A_v2_PROXY_header_over_IPv6_gives_the_client_address()
    {
        byte[] addresses =
        [
            .. IPAddress.Parse("2001:db8::7").GetAddressBytes(), .. IPAddress.Parse("2001:db8::1").GetAddressBytes(),
            0xC3, 0xCB, 0x00, 0x16,
        ];
        var (header, _) = await ReadAsync(V2(0x21, 0x21, addresses));

        Assert.Equal(new IPEndPoint(IPAddress.Parse("2001:db8::7"), 50123), header.Source);
    }

    [Fact]
    public async Task A_v2_LOCAL_header_keeps_the_address_of_the_connection()
    {
        // A health check of the balancer itself.
        var (header, rest) = await ReadAsync(V2(0x20, 0x00, []));

        Assert.Null(header.Source);
        Assert.Equal(SshIdentification, rest);
    }

    [Theory]
    [InlineData(0x11, 0x11)] // version 1 in the v2 format
    [InlineData(0x22, 0x11)] // an unknown command
    [InlineData(0x21, 0x12)] // DGRAM
    [InlineData(0x21, 0x41)] // an unknown address family
    public async Task A_v2_header_with_an_unknown_version_command_or_protocol_is_refused(int versionCommand, int family)
    {
        await RefusedAsync(V2((byte)versionCommand, (byte)family, Inet4("203.0.113.7", 1, "192.0.2.1", 22)));
    }

    [Fact]
    public async Task A_v2_header_with_a_too_short_address_block_is_refused()
    {
        await RefusedAsync(V2(0x21, 0x11, [1, 2, 3, 4, 5, 6, 7, 8]));
        await RefusedAsync(V2(0x21, 0x21, Inet4("203.0.113.7", 1, "192.0.2.1", 22))); // IPv6 needs 36 bytes
    }

    [Fact]
    public async Task A_v2_header_that_ends_before_its_declared_length_is_refused()
    {
        await RefusedAsync(V2(0x21, 0x11, Inet4("203.0.113.7", 1, "192.0.2.1", 22), declaredLength: 100));
    }

    [Fact]
    public async Task A_v2_header_with_a_huge_declared_length_is_refused_before_it_is_read()
    {
        await RefusedAsync(V2(0x21, 0x11, Inet4("203.0.113.7", 1, "192.0.2.1", 22), declaredLength: 60000));
    }

    [Fact]
    public async Task A_broken_v2_signature_is_refused()
    {
        var header = V2(0x21, 0x11, Inet4("203.0.113.7", 1, "192.0.2.1", 22));
        header[5] = 0x0E;

        await RefusedAsync(header);
    }
}
