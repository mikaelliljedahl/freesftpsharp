using System.Net;
using System.Net.Sockets;

namespace FreeSftpSharp.Tests.Infrastructure;

/// <summary>
/// A TCP proxy on loopback that forwards client data to the server at full speed, and server data to the
/// client in small pieces with a pause between them. The client then sends its SSH window adjustments
/// late, so the server's channel window is often empty while the server has more responses to send.
/// </summary>
public sealed class SlowDownstreamProxy : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly int _targetPort;
    private readonly int _chunkSize;
    private readonly TimeSpan _pause;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _acceptLoop;

    public SlowDownstreamProxy(int targetPort, int chunkSize = 16 * 1024, int pauseMilliseconds = 1)
    {
        _targetPort = targetPort;
        _chunkSize = chunkSize;
        _pause = TimeSpan.FromMilliseconds(pauseMilliseconds);
        _listener.Start();
        _acceptLoop = AcceptAsync();
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    private async Task AcceptAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                _ = HandleAsync(client);
            }
        }
        catch (Exception) when (_stop.IsCancellationRequested)
        {
        }
    }

    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        using (var server = new TcpClient())
        {
            await server.ConnectAsync(IPAddress.Loopback, _targetPort);
            var up = CopyAsync(client.GetStream(), server.GetStream(), 64 * 1024, TimeSpan.Zero);
            var down = CopyAsync(server.GetStream(), client.GetStream(), _chunkSize, _pause);
            await Task.WhenAny(up, down);
        }
    }

    private async Task CopyAsync(Stream from, Stream to, int chunkSize, TimeSpan pause)
    {
        var buffer = new byte[chunkSize];
        try
        {
            int read;
            while ((read = await from.ReadAsync(buffer, _stop.Token)) > 0)
            {
                await to.WriteAsync(buffer.AsMemory(0, read), _stop.Token);
                if (pause > TimeSpan.Zero)
                    await Task.Delay(pause, _stop.Token);
            }
        }
        catch (Exception)
        {
            // One side closed the connection, or the proxy stops.
        }
    }

    /// <summary>Stops the proxy and closes all its connections. A second call does nothing.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_stop.IsCancellationRequested)
            return;
        _stop.Cancel();
        _listener.Stop();
        await _acceptLoop;
    }
}
