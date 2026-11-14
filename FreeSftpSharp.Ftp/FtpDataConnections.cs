using System.Net;
using System.Net.Sockets;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Net;

namespace FreeSftpSharp.Ftp;

/// <summary>
/// The passive ports of the server (<see cref="FtpOptions.PassivePortRange"/>), shared by all sessions. A listener is
/// bound only to a port in the range; a port that is in use (by another session or another program) is skipped.
/// </summary>
internal sealed class FtpPassivePorts
{
    private readonly int _first;
    private readonly int _count;
    private int _next;

    public FtpPassivePorts(IOptions<FtpOptions> options)
    {
        var range = options.Value.Enabled ? options.Value.PassivePorts : (50000, 50000);
        _first = range.Item1;
        _count = range.Item2 - range.Item1 + 1;
    }

    /// <summary>A started listener on <paramref name="address"/> and a free port of the range, or null when every port is in use.</summary>
    public TcpListener? Bind(IPAddress address)
    {
        var start = (int)((uint)Interlocked.Increment(ref _next) % (uint)_count);
        for (var i = 0; i < _count; i++)
        {
            var port = _first + (start + i) % _count;
            var listener = new TcpListener(address, port);
            try
            {
                listener.Start(4);
                return listener;
            }
            catch (SocketException)
            {
                listener.Dispose();
            }
        }
        return null;
    }
}

/// <summary>Where the data connection of the next transfer comes from: a passive listener or an active target.</summary>
internal interface IFtpDataSource : IDisposable
{
    /// <summary>The connected data socket. Throws on a timeout or when the connection fails.</summary>
    Task<Socket> ConnectAsync(TimeSpan timeout, CancellationToken ct);
}

/// <summary>
/// A passive data connection (PASV, EPSV): the listener accepts only a connection from the address of the control
/// connection. A connection from another address (a stolen port, RFC 2577 section 5) is closed, and the listener waits on.
/// </summary>
internal sealed class FtpPassiveSource : IFtpDataSource
{
    private readonly TcpListener _listener;
    private readonly IPAddress _client;
    private readonly ILogger _logger;

    public FtpPassiveSource(TcpListener listener, IPAddress client, ILogger logger)
    {
        _listener = listener;
        _client = CidrNotation.Normalize(client);
        _logger = logger;
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public async Task<Socket> ConnectAsync(TimeSpan timeout, CancellationToken ct)
    {
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
        wait.CancelAfter(timeout);
        while (true)
        {
            var socket = await _listener.AcceptSocketAsync(wait.Token);
            var remote = socket.RemoteEndPoint is IPEndPoint ip ? CidrNotation.Normalize(ip.Address) : null;
            if (_client.Equals(remote))
                return socket;
            _logger.LogWarning("Refused a data connection from {Remote} to passive port {Port}: the control connection is from {Client}.",
                LogText.Clean(socket.RemoteEndPoint?.ToString()), Port, _client);
            socket.Dispose();
        }
    }

    public void Dispose() => _listener.Dispose();
}

/// <summary>An active data connection (PORT, EPRT): the server connects to the client.</summary>
internal sealed class FtpActiveSource : IFtpDataSource
{
    private readonly IPEndPoint _target;

    public FtpActiveSource(IPEndPoint target)
    {
        _target = target;
    }

    public async Task<Socket> ConnectAsync(TimeSpan timeout, CancellationToken ct)
    {
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
        wait.CancelAfter(timeout);
        var socket = new Socket(_target.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(_target, wait.Token);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
    }
}

/// <summary>The parsers of the address arguments of PORT and EPRT (RFC 959, RFC 2428).</summary>
internal static class FtpAddresses
{
    /// <summary>"h1,h2,h3,h4,p1,p2".</summary>
    public static IPEndPoint? ParsePort(string argument)
    {
        var parts = argument.Split(',', StringSplitOptions.TrimEntries);
        if (parts.Length != 6)
            return null;
        var bytes = new byte[6];
        for (var i = 0; i < 6; i++)
            if (!byte.TryParse(parts[i], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out bytes[i]))
                return null;
        return new IPEndPoint(new IPAddress(bytes.AsSpan(0, 4)), bytes[4] * 256 + bytes[5]);
    }

    /// <summary>"|1|132.235.1.2|6275|" or "|2|1080::8:800:200C:417A|5282|" (any delimiter of ASCII 33-126).</summary>
    public static IPEndPoint? ParseEprt(string argument)
    {
        if (argument.Length < 7 || argument[0] is < '!' or > '~')
            return null;
        var parts = argument.Split(argument[0]);
        if (parts.Length != 5 || parts[0].Length != 0 || parts[4].Length != 0)
            return null;
        if (!IPAddress.TryParse(parts[2], out var address)
            || !int.TryParse(parts[3], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var port)
            || port is < 1 or > 65535)
            return null;
        var family = parts[1] switch { "1" => AddressFamily.InterNetwork, "2" => AddressFamily.InterNetworkV6, _ => AddressFamily.Unknown };
        return address.AddressFamily == family ? new IPEndPoint(address, port) : null;
    }

    /// <summary>The 227 text of PASV: "Entering Passive Mode (h1,h2,h3,h4,p1,p2).".</summary>
    public static string PasvReply(IPAddress address, int port)
    {
        var b = address.GetAddressBytes();
        return $"Entering Passive Mode ({b[0]},{b[1]},{b[2]},{b[3]},{port / 256},{port % 256}).";
    }
}
