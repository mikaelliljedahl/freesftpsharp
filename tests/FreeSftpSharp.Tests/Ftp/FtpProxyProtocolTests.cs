using System.Net;
using System.Net.Sockets;
using System.Text;
using SshServer.Interfaces.Events;

namespace FreeSftpSharp.Tests.Ftp;

/// <summary>
/// The PROXY protocol on the FTP listener (#149, the <c>Proxy</c> section of #75): behind an allowed balancer the session
/// uses the client address of the header for the login rules, the connections and the events; a connection without the
/// header, or from a source that is not allowed, is closed before the greeting.
/// </summary>
public sealed class FtpProxyProtocolTests
{
    private const string Client = "203.0.113.7";

    private static Dictionary<string, string?> Settings(string allowed) => new()
    {
        ["Ftp:Tls:Mode"] = "Disabled",
        ["Proxy:AllowedSources"] = allowed,
    };

    private static byte[] V1Header(string client, int clientPort, int serverPort) =>
        Encoding.ASCII.GetBytes($"PROXY TCP4 {client} 127.0.0.1 {clientPort} {serverPort}\r\n");

    private static async Task LoginAsync(FtpRawClient raw, string username)
    {
        Assert.Equal(331, (await raw.CommandAsync("USER " + username)).Code);
        Assert.Equal(230, (await raw.CommandAsync("PASS " + FtpTestHost.Password)).Code);
    }

    /// <summary>True when the server closed the connection: no data, or a reset (it closed with unread data).</summary>
    private static async Task<bool> IsClosedAsync(TcpClient tcp)
    {
        try
        {
            return await tcp.GetStream().ReadAsync(new byte[8], TestContext.Current.CancellationToken) == 0;
        }
        catch (IOException)
        {
            return true;
        }
    }

    [Fact]
    public async Task Behind_an_allowed_balancer_the_connection_and_the_events_have_the_client_address_of_the_header()
    {
        await using var host = await FtpTestHost.StartAsync(Settings("127.0.0.1/32"));
        host.AddUser("alice");
        await using var raw = await host.RawAsync();
        await raw.SendBytesAsync(V1Header(Client, 40123, host.Port));

        Assert.Equal(220, (await raw.ReadAsync()).Code);
        await LoginAsync(raw, "alice");

        var connection = Assert.Single(host.Connections.GetAll());
        Assert.Equal(Client + ":40123", connection.RemoteEndPoint);
        Assert.Equal("alice", connection.Username);
        var login = Assert.Single(host.Events.Published.OfType<AuthEvent>(), e => e.Type == AuthEventType.LoginOk);
        Assert.Equal(Client, login.RemoteIp);
        Assert.Contains(Client, (await raw.CommandAsync("STAT")).Text);
    }

    [Fact]
    public async Task A_connection_from_the_balancer_without_the_header_is_closed_without_a_greeting()
    {
        await using var host = await FtpTestHost.StartAsync(Settings("127.0.0.1/32"));
        await using var raw = await host.RawAsync();
        await raw.SendAsync("USER alice");
        await raw.SendAsync("PASS " + FtpTestHost.Password);

        Assert.True(await raw.IsClosedAsync());
        Assert.Empty(host.Connections.GetAll());
        Assert.Contains(host.Logs.Messages, m => m.Contains("Refused the FTP connection") && m.Contains("PROXY"));
    }

    [Fact]
    public async Task A_header_from_a_source_that_is_not_allowed_is_refused()
    {
        await using var host = await FtpTestHost.StartAsync(Settings("10.0.0.0/8"));
        host.AddUser("alice");
        await using var raw = await host.RawAsync();
        await raw.SendBytesAsync(V1Header(Client, 40123, host.Port));

        Assert.True(await raw.IsClosedAsync());
        Assert.Empty(host.Connections.GetAll());
        Assert.DoesNotContain(host.Events.Published.OfType<AuthEvent>(), e => e.RemoteIp == Client);
    }

    [Fact]
    public async Task A_global_ip_rule_applies_to_the_client_address_of_the_header()
    {
        await using var host = await FtpTestHost.StartAsync(Settings("127.0.0.1/32"));
        host.Repository.ServerSettings.BlacklistedIps = [Client + "/32"];
        await using var raw = await host.RawAsync();
        await raw.SendBytesAsync(V1Header(Client, 40123, host.Port));

        Assert.Equal(421, (await raw.ReadAsync()).Code);
    }

    [Fact]
    public async Task A_passive_data_connection_through_the_balancer_needs_a_header_with_the_client_address()
    {
        await using var host = await FtpTestHost.StartAsync(Settings("127.0.0.1/32"));
        host.AddUser("alice");
        await host.StorageOf("alice").WriteAllAsync("/a.txt", "hello");
        await using var raw = await host.RawAsync();
        await raw.SendBytesAsync(V1Header(Client, 40123, host.Port));
        await raw.ReadAsync();
        await LoginAsync(raw, "alice");
        var (code, text) = await raw.CommandAsync("EPSV");
        Assert.Equal(229, code);
        var port = int.Parse(text.Split('|')[3], System.Globalization.CultureInfo.InvariantCulture);

        // From the balancer without a header, and with the header of another client: both closed.
        using var bare = new TcpClient();
        await bare.ConnectAsync(IPAddress.Loopback, port, TestContext.Current.CancellationToken);
        await bare.GetStream().WriteAsync(Encoding.ASCII.GetBytes("not a PROXY header\r\n"), TestContext.Current.CancellationToken);
        using var other = new TcpClient();
        await other.ConnectAsync(IPAddress.Loopback, port, TestContext.Current.CancellationToken);
        await other.GetStream().WriteAsync(V1Header("198.51.100.9", 40200, port), TestContext.Current.CancellationToken);
        using var data = new TcpClient();
        await data.ConnectAsync(IPAddress.Loopback, port, TestContext.Current.CancellationToken);
        await data.GetStream().WriteAsync(V1Header(Client, 40124, port), TestContext.Current.CancellationToken);

        await raw.SendAsync("RETR a.txt");
        Assert.Equal(150, (await raw.ReadAsync()).Code);
        using var reader = new StreamReader(data.GetStream());
        Assert.Equal("hello", await reader.ReadToEndAsync(TestContext.Current.CancellationToken));
        Assert.Equal(226, (await raw.ReadAsync()).Code);
        Assert.True(await IsClosedAsync(bare));
        Assert.True(await IsClosedAsync(other));
        Assert.Contains(host.Logs.Messages, m => m.Contains("Refused a data connection from 198.51.100.9"));
    }

    [Fact]
    public async Task Without_allowed_sources_a_PROXY_line_is_an_unknown_command()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:Tls:Mode"] = "Disabled" });
        await using var raw = await host.RawAsync();
        Assert.Equal(220, (await raw.ReadAsync()).Code);

        Assert.Equal(500, (await raw.CommandAsync($"PROXY TCP4 {Client} 127.0.0.1 40123 21")).Code);
    }
}
