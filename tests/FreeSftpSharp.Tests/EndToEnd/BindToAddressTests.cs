using System.Net;
using System.Net.Sockets;
using FreeSftpSharp.Tests.Infrastructure;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>A server with <c>BindToAddress</c> = 127.0.0.1.</summary>
public sealed class IPv4LoopbackOnlyFixture : SftpServerFixture
{
    protected override void ConfigureSettings(ServerSettings settings)
    {
        settings.BindToAddress = new List<string> { "127.0.0.1" };
    }
}

/// <summary><c>BindToAddress</c>: the server listens only on the listed addresses.</summary>
public sealed class BindToAddressTests : IClassFixture<IPv4LoopbackOnlyFixture>
{
    private readonly IPv4LoopbackOnlyFixture _server;

    public BindToAddressTests(IPv4LoopbackOnlyFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task The_server_answers_on_the_bound_address()
    {
        Assert.StartsWith("SSH-2.0-", await _server.ReadIdentificationAsync(IPAddress.Loopback));
        using var client = _server.Connect();
        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task The_server_does_not_listen_on_IPv6_loopback()
    {
        BindListenTests.SkipWithoutIPv6Loopback();

        var error = await Assert.ThrowsAnyAsync<SocketException>(() => _server.ReadIdentificationAsync(IPAddress.IPv6Loopback));
        Assert.Equal(SocketError.ConnectionRefused, error.SocketErrorCode);
    }
}

/// <summary>Without <c>BindToAddress</c> the server listens on all addresses, IPv4 and IPv6 (as before).</summary>
public sealed class BindListenTests : IClassFixture<SftpServerFixture>
{
    private readonly SftpServerFixture _server;

    public BindListenTests(SftpServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task Without_BindToAddress_the_server_listens_on_IPv4_and_IPv6()
    {
        Assert.StartsWith("SSH-2.0-", await _server.ReadIdentificationAsync(IPAddress.Loopback));

        SkipWithoutIPv6Loopback();
        Assert.StartsWith("SSH-2.0-", await _server.ReadIdentificationAsync(IPAddress.IPv6Loopback));
    }

    /// <summary>Some CI containers have no IPv6, not even ::1. Then the IPv6 checks cannot say anything.</summary>
    internal static void SkipWithoutIPv6Loopback()
    {
        if (!Socket.OSSupportsIPv6)
            Assert.Skip("IPv6 is not supported on this machine.");
        try
        {
            var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
            listener.Start();
            listener.Stop();
        }
        catch (SocketException)
        {
            Assert.Skip("IPv6 loopback (::1) is not available on this machine.");
        }
    }
}
