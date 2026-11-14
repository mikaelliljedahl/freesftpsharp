using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Net;
using SshServerModule.Proxy;

namespace FreeSftpSharp.Ftp;

/// <summary>
/// The FTP listener (issue #72): one task accepts the control connections of each bind address, one task runs each
/// session. Before a session starts it checks the global IP rules and the auto-ban, and the connections per address.
/// Does nothing while <see cref="FtpOptions.Enabled"/> is false.
/// </summary>
public sealed class FtpServer : IHostedService
{
    private const string Source = "FTP";

    private readonly FtpServices _services;
    private readonly ILogger _logger;
    private readonly List<TcpListener> _listeners = new();
    private readonly List<Task> _acceptLoops = new();
    private readonly ConcurrentDictionary<Task, bool> _sessions = new();
    private readonly ConcurrentDictionary<IPAddress, int> _perAddress = new();
    private CancellationTokenSource? _stopping;

    internal FtpServer(FtpServices services, ILogger<FtpServer> logger)
    {
        _services = services;
        _logger = logger;
    }

    /// <summary>The bound control endpoints (for tests with port 0, and for the log).</summary>
    public IReadOnlyList<IPEndPoint> LocalEndPoints => _listeners.Select(l => (IPEndPoint)l.LocalEndpoint).ToList();

    /// <summary>True while the control listeners are bound.</summary>
    public bool IsListening { get; private set; }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var options = _services.Options;
        if (!options.Enabled)
        {
            _logger.LogInformation("FTP is off. Set Ftp:Enabled to true to turn it on.");
            return;
        }
        if (options.Tls.Mode == FtpTlsMode.Disabled)
            _logger.LogWarning("FTP runs without TLS (Ftp:Tls:Mode is Disabled): passwords and files travel in clear text.");
        _ = _services.Certificate.ServerOptions; // load the certificate now, so a bad one stops the start

        _stopping = new CancellationTokenSource();
        try
        {
            foreach (var address in ListenAddresses.Resolve(options.BindAddresses, _logger))
            {
                var listener = new TcpListener(address, options.Port);
                if (address.Equals(IPAddress.IPv6Any))
                    listener.Server.DualMode = true;
                listener.Start(100);
                _listeners.Add(listener);
                _logger.LogInformation("FTP listening on {EndPoint} (TLS {Mode}, passive ports {Range}{Active}).", listener.LocalEndpoint,
                    options.Tls.Mode, options.PassivePortRange, options.AllowActiveMode ? ", active mode allowed" : "");
            }
        }
        catch
        {
            await StopListenersAsync();
            throw;
        }

        foreach (var listener in _listeners)
            _acceptLoops.Add(AcceptLoopAsync(listener, _stopping.Token));
        IsListening = true;
        await _services.PublishAsync(new SystemEvent(SystemEventType.Started)
        {
            Timestamp = _services.Time.GetUtcNow(), Source = Source,
            Message = "Listening on port " + string.Join(", ", LocalEndPoints.Select(e => e.Port).Distinct()) + ".",
        }, _logger);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_stopping == null)
            return;
        IsListening = false;
        await _services.PublishAsync(new SystemEvent(SystemEventType.Stopping) { Timestamp = _services.Time.GetUtcNow(), Source = Source }, _logger);
        await StopListenersAsync();
        try
        {
            await Task.WhenAll(_acceptLoops.Concat(_sessions.Keys)).WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
        }
        catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
        {
            _logger.LogWarning("Some FTP sessions did not end in time.");
        }
        _stopping.Dispose();
        _stopping = null;
    }

    private async Task StopListenersAsync()
    {
        if (_stopping != null)
            await _stopping.CancelAsync();
        foreach (var listener in _listeners)
            listener.Stop();
        _listeners.Clear();
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken stopping)
    {
        while (!stopping.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await listener.AcceptSocketAsync(stopping);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException
                                       || (ex is SocketException && stopping.IsCancellationRequested))
            {
                return;
            }
            catch (SocketException ex)
            {
                _logger.LogWarning(ex, "Could not accept an FTP connection.");
                continue;
            }

            var session = Task.Run(() => ServeAsync(socket, stopping), CancellationToken.None);
            _sessions[session] = true;
            _ = session.ContinueWith(t => _sessions.TryRemove(t, out _), TaskScheduler.Default);
        }
    }

    private async Task ServeAsync(Socket socket, CancellationToken stopping)
    {
        if (await ClientEndPointAsync(socket, stopping) is not { } client)
            return;
        var remote = CidrNotation.Normalize(client.Address);
        var filter = _services.Login.CheckAddress(remote);
        if (filter != IpFilterResult.Allowed)
        {
            _logger.LogWarning("Refused the FTP connection from {Remote}: {Reason}.", remote, filter);
            await RefuseAsync(socket, "421 Access denied.\r\n");
            return;
        }

        var limit = _services.Options.MaxConnectionsPerIp;
        var count = _perAddress.AddOrUpdate(remote, 1, (_, c) => c + 1);
        try
        {
            if (limit > 0 && count > limit)
            {
                _logger.LogWarning("Refused the FTP connection from {Remote}: it has {Count} connections already (Ftp:MaxConnectionsPerIp).", remote, count - 1);
                await RefuseAsync(socket, "421 Too many connections from your address.\r\n");
                return;
            }
            await new FtpSession(_services, socket, client, stopping).RunAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "The FTP session of {Remote} failed.", remote);
            socket.Dispose();
        }
        finally
        {
            if (_perAddress.AddOrUpdate(remote, 0, (_, c) => c - 1) <= 0)
                _perAddress.TryRemove(new KeyValuePair<IPAddress, int>(remote, 0));
        }
    }

    /// <summary>
    /// The address of the client: with the PROXY protocol (<c>Proxy:AllowedSources</c>, #75) the one of the header, which
    /// the connection must start with and only an allowed balancer may send; else the address of the connection. Null when
    /// the connection is refused (closed without a reply, before the greeting).
    /// </summary>
    private async Task<IPEndPoint?> ClientEndPointAsync(Socket socket, CancellationToken stopping)
    {
        var connection = socket.RemoteEndPoint as IPEndPoint ?? new IPEndPoint(IPAddress.None, 0);
        var proxy = _services.Proxy;
        if (!proxy.Enabled)
            return connection;
        try
        {
            return await proxy.AcceptAsync(socket, stopping) as IPEndPoint ?? connection;
        }
        catch (Exception ex) when (ex is ProxyProtocolException or IOException or SocketException or OperationCanceledException)
        {
            _logger.LogWarning("Refused the FTP connection from {Remote}: {Message}", connection, ex.Message);
            socket.Dispose();
            return null;
        }
    }

    private static async Task RefuseAsync(Socket socket, string reply)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await socket.SendAsync(Encoding.ASCII.GetBytes(reply), SocketFlags.None, timeout.Token);
            socket.Shutdown(SocketShutdown.Both);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
            // the client is gone
        }
        finally
        {
            socket.Dispose();
        }
    }
}
