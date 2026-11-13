using System.Diagnostics;
using System.Net.Sockets;
using FreeSftpSharp.Tests.Infrastructure;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>A server with ServerSettings.IdleTimeout = 1 second.</summary>
public sealed class ShortIdleTimeoutServerFixture : SftpServerFixture
{
    protected override int IdleTimeoutSeconds => 1;
}

/// <summary>
/// ServerSettings.IdleTimeout closes sessions without traffic (issue #27: before, the socket timeouts were
/// 0 and an idle client was never disconnected).
/// </summary>
public sealed class IdleTimeoutTests : IClassFixture<ShortIdleTimeoutServerFixture>
{
    private readonly ShortIdleTimeoutServerFixture _server;

    public IdleTimeoutTests(ShortIdleTimeoutServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task Client_that_sends_nothing_is_disconnected_after_the_idle_timeout()
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(SftpServerFixture.Host, _server.Port);
        var stream = tcp.GetStream();
        var stopwatch = Stopwatch.StartNew();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        // Read the identification line and KEXINIT, then wait until the server closes the connection.
        var buffer = new byte[4096];
        try
        {
            while (await stream.ReadAsync(buffer, cts.Token) > 0)
            {
            }
        }
        catch (IOException)
        {
            // A reset also counts as "disconnected".
        }

        Assert.False(cts.IsCancellationRequested, "The server did not close the idle connection within 15 seconds.");
        Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(10));
    }

    [Fact]
    public void Idle_sftp_session_is_disconnected_after_the_idle_timeout()
    {
        using var client = _server.Connect();
        Assert.True(client.IsConnected);

        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (client.IsConnected && DateTime.UtcNow < deadline)
            Thread.Sleep(100);

        Assert.False(client.IsConnected, "The idle session was not disconnected.");
    }
}
