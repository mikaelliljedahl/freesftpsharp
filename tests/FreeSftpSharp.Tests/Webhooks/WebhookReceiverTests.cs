namespace FreeSftpSharp.Tests.Webhooks;

/// <summary>The receiver of the webhook tests must only use a free port of its own: test classes run in parallel in one process.</summary>
public sealed class WebhookReceiverTests
{
    [Fact]
    public async Task Receivers_started_together_each_get_their_own_free_port_and_never_the_default_port_5000()
    {
        // The test output can have the appsettings.json of FxSshSftpServer, with a Kestrel endpoint on http://localhost:5000
        // (FxSshSftpServer and ServerConsoleApp both copy their appsettings.json there; the one that is copied last wins).
        // A receiver that took it would fail as soon as a second receiver, or any server on the machine, has the port.
        using var occupied = new ListenerHolder(TryListenOn5000()); // null when another process on the machine already has it: the same situation
        await using var first = await WebhookReceiver.StartAsync();
        await using var second = await WebhookReceiver.StartAsync();

        var ports = new[] { first, second }.Select(r => new Uri(r.BaseUrl).Port).ToList();
        Assert.DoesNotContain(5000, ports);
        Assert.Equal(2, ports.Distinct().Count());
    }

    private sealed class ListenerHolder(System.Net.Sockets.TcpListener? listener) : IDisposable
    {
        public void Dispose() => listener?.Stop();
    }

    private static System.Net.Sockets.TcpListener? TryListenOn5000()
    {
        try
        {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 5000);
            listener.Start();
            return listener;
        }
        catch (System.Net.Sockets.SocketException)
        {
            return null;
        }
    }
}
