using System.Buffers;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Ftp;

internal enum FtpListKind
{
    /// <summary>LIST: "ls -l" lines.</summary>
    List,
    /// <summary>NLST: the names only.</summary>
    Names,
    /// <summary>MLSD: the facts of RFC 3659.</summary>
    Machine,
}

/// <summary>The data connections (PASV, EPSV, PORT, EPRT) and the transfers (LIST, NLST, MLSD, RETR, STOR, APPE).</summary>
internal sealed partial class FtpSession
{
    private const int BufferSize = 64 * 1024;

    private TimeSpan DataTimeout => TimeSpan.FromSeconds(_options.DataTimeoutSeconds);

    private async Task PasvAsync()
    {
        if (_epsvAll)
        {
            await ReplyAsync(503, "EPSV ALL was sent; use EPSV.");
            return;
        }
        var advertised = _options.ExternalAddress ?? _local;
        if (advertised.AddressFamily != AddressFamily.InterNetwork || _local.AddressFamily != AddressFamily.InterNetwork)
        {
            await ReplyAsync(425, "PASV needs IPv4; use EPSV.");
            return;
        }
        if (await BindPassiveAsync() is { } port)
            await ReplyAsync(227, FtpAddresses.PasvReply(advertised, port));
    }

    private async Task EpsvAsync(string argument)
    {
        var protocol = argument.Trim();
        if (protocol.Equals("ALL", StringComparison.OrdinalIgnoreCase))
        {
            _epsvAll = true;
            await ReplyAsync(200, "EPSV ALL accepted.");
            return;
        }
        var family = _local.AddressFamily == AddressFamily.InterNetwork ? "1" : "2";
        if (protocol.Length > 0 && protocol != family)
        {
            await ReplyAsync(522, $"Network protocol not supported, use ({family}).");
            return;
        }
        if (await BindPassiveAsync() is { } port)
            await ReplyAsync(229, $"Entering Extended Passive Mode (|||{port}|).");
    }

    /// <summary>A passive listener on the local address of the control connection and a port of the range; null after a 425.</summary>
    private async Task<int?> BindPassiveAsync()
    {
        ClearDataSource();
        var listener = _services.PassivePorts.Bind(_local);
        if (listener == null)
        {
            _logger.LogWarning("No free passive port in {Range} for FTP connection {ConnectionId}.", _options.PassivePortRange, _connectionId);
            await ReplyAsync(425, "No free passive port; try again later.");
            return null;
        }
        var source = new FtpPassiveSource(listener, _remote, _services.Proxy, _logger);
        _data = source;
        return source.Port;
    }

    /// <summary>PORT and EPRT: only when allowed, only to the client itself and to a port of 1024 or higher (no FTP bounce, RFC 2577).</summary>
    private async Task ActiveAsync(IPEndPoint? target)
    {
        if (!_options.AllowActiveMode)
        {
            await ReplyAsync(502, "Active mode is off; use PASV or EPSV.");
            return;
        }
        if (_epsvAll)
        {
            await ReplyAsync(503, "EPSV ALL was sent; use EPSV.");
            return;
        }
        if (target == null)
        {
            await ReplyAsync(501, "Syntax error in the address.");
            return;
        }
        var address = SshServer.Interfaces.Net.CidrNotation.Normalize(target.Address);
        if (!address.Equals(_remote) || target.Port < 1024)
        {
            _logger.LogWarning("Refused the active data address {Target} of FTP connection {ConnectionId} from {RemoteEndPoint}.",
                target, _connectionId, _remoteEndPoint);
            await ReplyAsync(504, "The data address must be the client address and a port of 1024 or higher.");
            return;
        }
        ClearDataSource();
        _data = new FtpActiveSource(new IPEndPoint(address, target.Port));
        await ReplyAsync(200, "PORT command successful.");
    }

    private void ClearDataSource()
    {
        _data?.Dispose();
        _data = null;
    }

    /// <summary>Checks that a transfer can start; replies and returns false when not.</summary>
    private async Task<bool> CanTransferAsync()
    {
        if (_data == null)
        {
            await ReplyAsync(425, "Use PASV or EPSV first.");
            return false;
        }
        if (TlsRequired && !_protectData)
        {
            await ReplyAsync(521, "This server needs protected data connections: send PBSZ 0 and PROT P.");
            ClearDataSource();
            return false;
        }
        return true;
    }

    /// <summary>
    /// Sends 150, connects the data connection and makes the TLS handshake on it with PROT P (the server is the TLS server,
    /// RFC 4217 section 9). Null after a 425.
    /// </summary>
    private async Task<Stream?> OpenDataAsync(string what)
    {
        var source = _data!;
        _data = null;
        await ReplyAsync(150, "Opening data connection for " + what + ".");
        Stream? stream = null;
        try
        {
            var socket = await source.ConnectAsync(DataTimeout, Ct);
            stream = new NetworkStream(socket, ownsSocket: true);
            if (_protectData)
            {
                var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
                stream = ssl;
                using var handshake = CancellationTokenSource.CreateLinkedTokenSource(Ct);
                handshake.CancelAfter(DataTimeout);
                await ssl.AuthenticateAsServerAsync(_services.Certificate.DataOptions!, handshake.Token);
            }
            return stream;
        }
        catch (Exception ex) when (IsDataFailure(ex))
        {
            _logger.LogInformation("The data connection of FTP connection {ConnectionId} failed: {Message}", _connectionId, ex.Message);
            if (stream != null)
                await stream.DisposeAsync();
            await ReplyAsync(425, "Cannot open the data connection.");
            return null;
        }
        finally
        {
            source.Dispose();
        }
    }

    /// <summary>A failure of the data connection: the client, the network or the data timeout (not the end of the session).</summary>
    private bool IsDataFailure(Exception ex) =>
        ex is IOException or SocketException or AuthenticationException or ObjectDisposedException
        || (ex is OperationCanceledException && !Ct.IsCancellationRequested);

    private static async Task CloseDataAsync(Stream stream)
    {
        try
        {
            if (stream is SslStream ssl)
                await ssl.ShutdownAsync().WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (Exception ex) when (ex is IOException or SocketException or TimeoutException or ObjectDisposedException or InvalidOperationException)
        {
            // the client closed first
        }
        await stream.DisposeAsync();
    }

    private async Task ListAsync(string argument, FtpListKind kind)
    {
        var path = Resolve(FtpListing.WithoutOptions(argument));
        var lines = new List<string>();
        var entry = await FileSystem.StatAsync(path, true, Ct);
        if (entry == null)
        {
            await ReplyAsync(550, "No such file or directory.");
            return;
        }
        if (!entry.IsDirectory)
        {
            if (kind == FtpListKind.Machine)
            {
                await ReplyAsync(501, "Not a directory; use MLST.");
                return;
            }
            lines.Add(kind == FtpListKind.Names ? entry.Name : FtpListing.ListLine(entry, _services.Time.GetUtcNow().UtcDateTime));
        }
        else
        {
            var now = _services.Time.GetUtcNow().UtcDateTime;
            var entries = new List<FileSystemEntry>();
            await foreach (var child in FileSystem.ListAsync(path, Ct))
                entries.Add(child);
            foreach (var child in entries.OrderBy(e => e.Name, StringComparer.Ordinal))
                lines.Add(kind switch
                {
                    FtpListKind.Names => child.Name,
                    FtpListKind.Machine => FtpListing.Facts(child, child.Name),
                    _ => FtpListing.ListLine(child, now),
                });
        }

        if (!await CanTransferAsync())
            return;
        _restart = 0;
        var data = await OpenDataAsync("the directory listing");
        if (data == null)
            return;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            timeout.CancelAfter(DataTimeout);
            await data.WriteAsync(FtpListing.Text(lines), timeout.Token);
            await CloseDataAsync(data);
            data = null;
            await ReplyAsync(226, "Transfer complete.");
        }
        catch (Exception ex) when (IsDataFailure(ex))
        {
            await ReplyAsync(426, "Connection closed; transfer aborted.");
        }
        finally
        {
            if (data != null)
                await data.DisposeAsync();
        }
    }

    private async Task RetrAsync(string path)
    {
        if (!await CanTransferAsync())
            return;
        var offset = _restart;
        _restart = 0;
        IFileHandle handle;
        try
        {
            handle = await FileSystem.OpenAsync(path, FileOpenFlags.Read, null, Ct);
        }
        catch (FileSystemException)
        {
            ClearDataSource();
            throw;
        }

        Stream? data = null;
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            data = await OpenDataAsync(VirtualPath.GetName(path));
            if (data == null)
                return;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            var position = offset;
            while (true)
            {
                int read;
                try
                {
                    read = await handle.ReadAsync(position, buffer.AsMemory(0, BufferSize), Ct);
                }
                catch (FileSystemException ex)
                {
                    await data.DisposeAsync();
                    data = null;
                    var (code, text) = FtpErrors.Of(ex);
                    await ReplyAsync(code, text);
                    return;
                }
                if (read == 0)
                    break;
                timeout.CancelAfter(DataTimeout);
                await data.WriteAsync(buffer.AsMemory(0, read), timeout.Token);
                position += read;
            }
            await CloseDataAsync(data);
            data = null;
            await ReplyAsync(226, "Transfer complete.");
        }
        catch (Exception ex) when (IsDataFailure(ex))
        {
            await ReplyAsync(426, "Connection closed; transfer aborted.");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            if (data != null)
                await data.DisposeAsync();
            try
            {
                await handle.DisposeAsync();
            }
            catch (FileSystemException ex)
            {
                _logger.LogWarning(ex, "Could not close a downloaded file of FTP connection {ConnectionId}.", _connectionId);
            }
        }
    }

    /// <summary>
    /// STOR (a new file, or a resume at the REST offset) and APPE. The file is finished only when the client closed the
    /// data connection normally; a lost connection aborts it (<see cref="IFileHandle.AbortAsync"/>).
    /// </summary>
    private async Task StoreAsync(string path, bool append)
    {
        if (!await CanTransferAsync())
            return;
        var offset = _restart;
        _restart = 0;
        var flags = FileOpenFlags.Write | FileOpenFlags.Create
                    | (append ? FileOpenFlags.Append : offset == 0 ? FileOpenFlags.Truncate : FileOpenFlags.None);
        IFileHandle handle;
        try
        {
            handle = await FileSystem.OpenAsync(path, flags, null, Ct);
        }
        catch (FileSystemException)
        {
            ClearDataSource();
            throw;
        }

        Stream? data = null;
        var finished = false;
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            data = await OpenDataAsync(VirtualPath.GetName(path));
            if (data == null)
                return;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            var position = offset;
            while (true)
            {
                timeout.CancelAfter(DataTimeout);
                var read = await data.ReadAsync(buffer.AsMemory(0, BufferSize), timeout.Token);
                if (read == 0)
                    break;
                await handle.WriteAsync(position, buffer.AsMemory(0, read), Ct);
                position += read;
            }
            await CloseDataAsync(data);
            data = null;
            finished = true;
            await handle.DisposeAsync(); // the last write; a quota or hook failure is thrown here
            await ReplyAsync(226, "Transfer complete.");
        }
        catch (FileSystemException ex)
        {
            var (code, text) = FtpErrors.Of(ex);
            await ReplyAsync(code, text);
        }
        catch (Exception ex) when (IsDataFailure(ex))
        {
            await ReplyAsync(426, "Connection closed; transfer aborted.");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            if (data != null)
                await data.DisposeAsync();
            if (!finished)
                await AbortAsync(handle);
        }
    }

    private async Task AbortAsync(IFileHandle handle)
    {
        try
        {
            await handle.AbortAsync();
        }
        catch (FileSystemException ex)
        {
            _logger.LogWarning(ex, "Could not abort an upload of FTP connection {ConnectionId}.", _connectionId);
        }
    }
}
