using System.Net;
using System.Net.Sockets;
using System.Text;
using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Renci.SshNet;
using SshServer.Interfaces.Events;
using SshServerModule.Events;
using SshServerModule.Proxy;

namespace FreeSftpSharp.Tests.Proxy;

/// <summary>The server behind a load balancer on 127.0.0.1 that sends the PROXY protocol (<c>Proxy:AllowedSources</c>).</summary>
public sealed class ProxyServerFixture : SftpServerFixture
{
    public RecordingEventSink Sink { get; } = new();

    protected override IEventBus CreateEventBus() => new ChannelEventBus([Sink], [], NullLogger<ChannelEventBus>.Instance);

    protected override ProxyProtocolOptions? CreateProxyOptions() => ProxyProtocolOptions.Create(["127.0.0.1/32"]);
}

/// <summary>The server with a balancer address that is not loopback: every connection of the tests is from a source that is not allowed.</summary>
public sealed class ProxyFromOtherSourceFixture : SftpServerFixture
{
    protected override ProxyProtocolOptions? CreateProxyOptions() => ProxyProtocolOptions.Create(["10.0.0.0/8"]);
}

/// <summary>
/// A TCP forwarder like HAProxy with <c>send-proxy-v2</c>: it sends a PROXY v2 header with a client address of the test,
/// then forwards the bytes in both directions.
/// </summary>
internal sealed class ProxyV2Forwarder : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly int _target;
    private readonly IPEndPoint _client;
    private readonly CancellationTokenSource _stop = new();

    public ProxyV2Forwarder(int target, IPEndPoint client)
    {
        _target = target;
        _client = client;
        _listener.Start();
        _ = AcceptAsync();
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public static byte[] Header(IPEndPoint client, int serverPort)
    {
        byte[] signature = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];
        return
        [
            .. signature, 0x21, 0x11, 0x00, 12, .. client.Address.GetAddressBytes(), 127, 0, 0, 1,
            (byte)(client.Port >> 8), (byte)client.Port, (byte)(serverPort >> 8), (byte)serverPort,
        ];
    }

    private async Task AcceptAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var accepted = await _listener.AcceptTcpClientAsync(_stop.Token);
                _ = ForwardAsync(accepted);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (SocketException)
        {
        }
    }

    private async Task ForwardAsync(TcpClient accepted)
    {
        using (accepted)
        using (var server = new TcpClient())
        {
            try
            {
                await server.ConnectAsync(IPAddress.Loopback, _target, _stop.Token);
                var toServer = server.GetStream();
                await toServer.WriteAsync(Header(_client, _target), _stop.Token);
                var fromClient = accepted.GetStream();
                await Task.WhenAny(fromClient.CopyToAsync(toServer, _stop.Token), toServer.CopyToAsync(fromClient, _stop.Token));
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
            {
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        _stop.Cancel();
        _listener.Stop();
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// The PROXY protocol on the SSH listener (#75): behind the balancer the server sees and logs the real client address,
/// and a connection without the header, or from a source that is not the balancer, is refused before the SSH handshake.
/// </summary>
public sealed class ProxyProtocolEndToEndTests : IClassFixture<ProxyServerFixture>
{
    private readonly ProxyServerFixture _server;

    public ProxyProtocolEndToEndTests(ProxyServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task Behind_the_balancer_the_connection_and_the_audit_events_have_the_real_client_address()
    {
        var client = new IPEndPoint(IPAddress.Parse("203.0.113.7"), 40123);
        await using var balancer = new ProxyV2Forwarder(_server.Port, client);
        using var sftp = new SftpClient("127.0.0.1", balancer.Port, _server.Username, _server.Password);

        await sftp.ConnectAsync(TestContext.Current.CancellationToken);

        Assert.Contains(_server.Connections.GetAll(), c => c.RemoteEndPoint == "203.0.113.7:40123" && c.Username == _server.Username);
        var login = Assert.Single(await _server.Sink.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.LoginOk && e.RemoteIp == "203.0.113.7"));
        Assert.Equal(_server.Username, login.Username);
    }

    [Fact]
    public async Task A_connection_from_the_balancer_without_the_header_is_refused()
    {
        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        await tcp.ConnectAsync(IPAddress.Loopback, _server.Port, TestContext.Current.CancellationToken);
        var stream = tcp.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes("SSH-2.0-OpenSSH_9.6\r\n"), TestContext.Current.CancellationToken);

        Assert.Equal("", await ReadAsync(stream));
    }

    [Fact]
    public async Task A_malformed_header_is_refused()
    {
        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        await tcp.ConnectAsync(IPAddress.Loopback, _server.Port, TestContext.Current.CancellationToken);
        var stream = tcp.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes("PROXY TCP4 203.0.113.7 127.0.0.1 99999 22\r\nSSH-2.0-x\r\n"), TestContext.Current.CancellationToken);

        Assert.Equal("", await ReadAsync(stream));
    }

    internal static async Task<string> ReadAsync(NetworkStream stream)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var buffer = new byte[256];
        try
        {
            var read = await stream.ReadAsync(buffer, timeout.Token);
            return Encoding.ASCII.GetString(buffer, 0, read);
        }
        catch (IOException)
        {
            return ""; // reset by the server
        }
    }
}

/// <summary>A connection from a source that is not an allowed balancer is refused, also with a valid header.</summary>
public sealed class ProxyProtocolSourceTests : IClassFixture<ProxyFromOtherSourceFixture>
{
    private readonly ProxyFromOtherSourceFixture _server;

    public ProxyProtocolSourceTests(ProxyFromOtherSourceFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task A_direct_connection_from_a_source_that_is_not_allowed_is_refused()
    {
        Assert.Equal("", await _server.ReadIdentificationAsync());
    }

    [Fact]
    public async Task A_header_from_a_source_that_is_not_allowed_is_refused()
    {
        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        await tcp.ConnectAsync(IPAddress.Loopback, _server.Port, TestContext.Current.CancellationToken);
        var stream = tcp.GetStream();
        await stream.WriteAsync(ProxyV2Forwarder.Header(new IPEndPoint(IPAddress.Parse("203.0.113.7"), 40123), _server.Port), TestContext.Current.CancellationToken);

        Assert.Equal("", await ProxyProtocolEndToEndTests.ReadAsync(stream));
    }
}
