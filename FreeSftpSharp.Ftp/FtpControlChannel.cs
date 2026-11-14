using System.Net.Security;
using System.Text;

namespace FreeSftpSharp.Ftp;

/// <summary>The result of <see cref="FtpControlChannel.ReadLineAsync"/>.</summary>
internal enum FtpLineStatus
{
    Line,
    /// <summary>The client closed the connection.</summary>
    Closed,
    /// <summary>The line is longer than <see cref="FtpOptions.MaxCommandLineBytes"/>.</summary>
    TooLong,
}

/// <summary>
/// The control connection: reads command lines (UTF-8, CRLF or LF, Telnet IAC sequences removed) with a length limit, writes
/// replies, and switches to TLS after <c>AUTH TLS</c>.
/// </summary>
internal sealed class FtpControlChannel : IAsyncDisposable
{
    private const byte Iac = 0xFF;
    private static readonly Encoding Utf8 = new UTF8Encoding(false, false);

    private readonly byte[] _buffer = new byte[FtpOptions.MaxCommandLineBytes];
    private int _start;
    private int _end;
    private Stream _stream;

    public FtpControlChannel(Stream stream)
    {
        _stream = stream;
    }

    /// <summary>True after <see cref="UpgradeToTlsAsync"/>.</summary>
    public bool IsSecure => _stream is SslStream;

    /// <summary>True when the client sent bytes after the last line that were not read yet.</summary>
    public bool HasBufferedData => _end > _start;

    /// <summary>Reads the next line, without its line end.</summary>
    public async ValueTask<(FtpLineStatus Status, string Line)> ReadLineAsync(CancellationToken ct)
    {
        var line = new List<byte>(64);
        while (true)
        {
            while (_start < _end)
            {
                var b = _buffer[_start++];
                if (b == (byte)'\n')
                {
                    if (line.Count > 0 && line[^1] == (byte)'\r')
                        line.RemoveAt(line.Count - 1);
                    return (FtpLineStatus.Line, Utf8.GetString(RemoveTelnet(line)));
                }
                line.Add(b);
                if (line.Count >= FtpOptions.MaxCommandLineBytes)
                    return (FtpLineStatus.TooLong, "");
            }

            _start = 0;
            _end = await _stream.ReadAsync(_buffer, ct);
            if (_end == 0)
                return (FtpLineStatus.Closed, "");
        }
    }

    /// <summary>
    /// Removes Telnet commands (RFC 854) that some clients send before ABOR: IAC with a command byte, and with an option
    /// byte for WILL, WONT, DO and DONT. IAC IAC is a literal 0xFF.
    /// </summary>
    internal static byte[] RemoveTelnet(List<byte> line)
    {
        if (!line.Contains(Iac))
            return line.ToArray();
        var result = new List<byte>(line.Count);
        for (var i = 0; i < line.Count; i++)
        {
            if (line[i] != Iac)
            {
                result.Add(line[i]);
                continue;
            }
            if (i + 1 >= line.Count)
                break;
            var command = line[++i];
            if (command == Iac)
                result.Add(Iac);
            else if (command is >= 0xFB and <= 0xFE)
                i++; // WILL, WONT, DO, DONT: skip the option byte
        }
        return result.ToArray();
    }

    public async ValueTask WriteAsync(string reply, CancellationToken ct)
    {
        await _stream.WriteAsync(Utf8.GetBytes(reply), ct);
        await _stream.FlushAsync(ct);
    }

    public ValueTask ReplyAsync(int code, string text, CancellationToken ct) => WriteAsync(FtpReply.Format(code, text), ct);

    /// <summary>The TLS handshake on the control connection (the server side).</summary>
    public async ValueTask UpgradeToTlsAsync(SslServerAuthenticationOptions options, TimeSpan timeout, CancellationToken ct)
    {
        var ssl = new SslStream(_stream, leaveInnerStreamOpen: false);
        using var handshake = CancellationTokenSource.CreateLinkedTokenSource(ct);
        handshake.CancelAfter(timeout);
        try
        {
            await ssl.AuthenticateAsServerAsync(options, handshake.Token);
        }
        catch
        {
            await ssl.DisposeAsync();
            throw;
        }
        _stream = ssl;
        _start = _end = 0;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (_stream is SslStream ssl)
                await ssl.ShutdownAsync().WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
            // the client may be gone already
        }
        await _stream.DisposeAsync();
    }
}
