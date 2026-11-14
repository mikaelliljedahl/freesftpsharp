using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Net;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.Users;

namespace FreeSftpSharp.Ftp;

/// <summary>
/// One FTP control connection (RFC 959, with RFC 2228/4217 TLS, RFC 2428 and RFC 3659): the login, the TLS switch and
/// the dispatch of the commands. Commands run one after the other; a transfer blocks the control connection until it
/// ends. Every file operation goes through the decorated <see cref="IFileSystem"/> of the user.
/// </summary>
internal sealed partial class FtpSession
{
    private static readonly HashSet<string> BeforeLogin = new(StringComparer.Ordinal)
    {
        "USER", "PASS", "AUTH", "PBSZ", "PROT", "FEAT", "SYST", "NOOP", "QUIT", "OPTS", "HELP", "CLNT",
    };

    private readonly FtpServices _services;
    private readonly FtpOptions _options;
    private readonly Socket _socket;
    private readonly FtpControlChannel _channel;
    private readonly ILogger _logger;
    private readonly IPAddress _remote;
    private readonly IPAddress _local;
    private readonly string _remoteEndPoint;
    private readonly CancellationTokenSource _cts;
    private readonly TaskCompletionSource _done = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private Guid _connectionId;
    private volatile string? _disconnectReason;

    private string? _pendingUser;
    private int _failedLogins;
    private User? _user;
    private string? _method;
    private IFileSystem? _fileSystem;
    private string _cwd = VirtualPath.Root;
    private bool _protectData;
    private bool _epsvAll;
    private long _restart;
    private string? _renameFrom;
    private IFtpDataSource? _data;

    /// <param name="client">The address of the client: of the connection, or of the PROXY header behind a load balancer.</param>
    public FtpSession(FtpServices services, Socket socket, IPEndPoint client, CancellationToken serverStopping)
    {
        _services = services;
        _options = services.Options;
        _socket = socket;
        _channel = new FtpControlChannel(new NetworkStream(socket, ownsSocket: true));
        _logger = services.Loggers.CreateLogger<FtpSession>();
        _remote = CidrNotation.Normalize(client.Address);
        _local = CidrNotation.Normalize(((IPEndPoint)socket.LocalEndPoint!).Address);
        _remoteEndPoint = new IPEndPoint(_remote, client.Port).ToString();
        _cts = CancellationTokenSource.CreateLinkedTokenSource(serverStopping);
    }

    private CancellationToken Ct => _cts.Token;
    private IFileSystem FileSystem => _fileSystem!;
    private bool TlsRequired => _options.Tls.Mode == FtpTlsMode.Required;

    /// <summary>Runs the session until the client quits, the connection fails, or the server stops.</summary>
    public async Task RunAsync()
    {
        var connection = _services.Connections.Register(new ConnectionRegistration(ConnectionProtocols.Ftp, _remoteEndPoint, DisconnectAsync));
        _connectionId = connection.Id;
        _logger.LogInformation("Accepted an FTP client from {RemoteEndPoint} (connection {ConnectionId}).", _remoteEndPoint, _connectionId);
        try
        {
            await _channel.ReplyAsync(220, _options.Banner, Ct);
            await LoopAsync();
        }
        catch (OperationCanceledException) when (_cts.IsCancellationRequested)
        {
            await TryReplyAsync(421, _disconnectReason is { } reason ? "Disconnected: " + reason.ReplaceLineEndings(" ") : "The server is shutting down.");
        }
        catch (Exception ex) when (ex is IOException or SocketException or AuthenticationException or ObjectDisposedException)
        {
            _logger.LogDebug(ex, "FTP connection {ConnectionId} ended: {Message}", _connectionId, ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "FTP connection {ConnectionId} failed.", _connectionId);
        }
        finally
        {
            await EndAsync();
        }
    }

    private async Task LoopAsync()
    {
        while (true)
        {
            FtpLineStatus status;
            string line;
            using (var idle = CancellationTokenSource.CreateLinkedTokenSource(Ct))
            {
                idle.CancelAfter(TimeSpan.FromSeconds(_options.IdleTimeoutSeconds));
                try
                {
                    (status, line) = await _channel.ReadLineAsync(idle.Token);
                }
                catch (OperationCanceledException) when (!Ct.IsCancellationRequested)
                {
                    await TryReplyAsync(421, "Idle timeout; closing the connection.");
                    return;
                }
            }

            if (status == FtpLineStatus.Closed)
                return;
            if (status == FtpLineStatus.TooLong)
            {
                _logger.LogWarning("FTP connection {ConnectionId} from {RemoteEndPoint} sent a command line over {Max} bytes; closing it.",
                    _connectionId, _remoteEndPoint, FtpOptions.MaxCommandLineBytes);
                await TryReplyAsync(500, "Command line too long.");
                return;
            }

            if (FtpCommand.Parse(line) is not { } command)
            {
                await ReplyAsync(500, "Syntax error, command unrecognized.");
                continue;
            }
            _logger.LogDebug("FTP {ConnectionId} < {Command}", _connectionId, LogText.Clean(command.ToString()));
            if (command.Verb != "RNTO")
                _renameFrom = null; // RNTO must follow RNFR at once (RFC 959 section 4.1.3)
            if (!await HandleAsync(command))
                return;
        }
    }

    private ValueTask ReplyAsync(int code, string text) => _channel.ReplyAsync(code, text, Ct);

    /// <summary>A last reply before the connection is closed; it may fail when the client is gone.</summary>
    private async Task TryReplyAsync(int code, string text)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await _channel.ReplyAsync(code, text, timeout.Token);
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
            // the client is gone
        }
    }

    /// <summary>The disconnect of the connection registry (an administrator, or a disabled user).</summary>
    private async Task DisconnectAsync(string reason)
    {
        _disconnectReason = reason;
        try
        {
            await _cts.CancelAsync();
        }
        catch (ObjectDisposedException)
        {
            return;
        }
        await _done.Task.WaitAsync(TimeSpan.FromSeconds(5)).ContinueWith(_ => { }, TaskScheduler.Default);
    }

    private async Task EndAsync()
    {
        _data?.Dispose();
        _data = null;
        var info = _services.Connections.Get(_connectionId);
        _services.Connections.Unregister(_connectionId);
        if (_user != null)
            await _services.PublishAsync(new AuthEvent(AuthEventType.Logout)
            {
                Timestamp = _services.Time.GetUtcNow(), Username = _user.Username, RemoteIp = _remote.ToString(), Protocol = ConnectionProtocols.Ftp,
                Method = _method, SessionId = _connectionId.ToString(),
            }, _logger);
        _logger.LogInformation("FTP connection {ConnectionId} from {RemoteEndPoint} closed{User}.", _connectionId, _remoteEndPoint,
            info?.Username is { } name ? " (user " + LogText.Clean(name) + ")" : "");
        await _channel.DisposeAsync();
        _socket.Dispose();
        _cts.Dispose();
        _done.TrySetResult();
    }

    /// <summary>Runs one command. False: close the connection.</summary>
    private async Task<bool> HandleAsync(FtpCommand command)
    {
        if (_user == null && !BeforeLogin.Contains(command.Verb))
        {
            await ReplyAsync(530, "Please log in with USER and PASS.");
            return true;
        }

        var argument = command.Argument;
        try
        {
            switch (command.Verb)
            {
                case "USER": await UserAsync(argument); return true;
                case "PASS": return await PassAsync(argument);
                case "AUTH": return await AuthAsync(argument);
                case "PBSZ": await PbszAsync(argument); return true;
                case "PROT": await ProtAsync(argument); return true;
                case "FEAT": await ReplyAsync(211, Features()); return true;
                case "SYST": await ReplyAsync(215, "UNIX Type: L8"); return true;
                case "NOOP": await ReplyAsync(200, "OK."); return true;
                case "QUIT": await ReplyAsync(221, "Goodbye."); return false;
                case "OPTS": await OptsAsync(argument); return true;
                case "HELP": await ReplyAsync(214, "The commands are:\nUSER PASS AUTH PBSZ PROT FEAT SYST NOOP QUIT OPTS HELP CLNT TYPE MODE STRU\n"
                                                    + "PWD CWD CDUP MKD RMD DELE RNFR RNTO SIZE MDTM REST ALLO ABOR STAT SITE\nPASV EPSV PORT EPRT LIST NLST MLSD MLST RETR STOR APPE\nEnd."); return true;
                case "CLNT":
                    if (argument.Length > 0)
                        _services.Connections.SetClientVersion(_connectionId, argument.Length > 200 ? argument[..200] : argument);
                    await ReplyAsync(200, "OK.");
                    return true;
                case "TYPE": await TypeAsync(argument); return true;
                case "MODE": await (argument.Trim().Equals("S", StringComparison.OrdinalIgnoreCase) ? ReplyAsync(200, "Mode set to S.") : ReplyAsync(504, "Only mode S is supported.")); return true;
                case "STRU": await (argument.Trim().Equals("F", StringComparison.OrdinalIgnoreCase) ? ReplyAsync(200, "Structure set to F.") : ReplyAsync(504, "Only structure F is supported.")); return true;
                case "ALLO": await ReplyAsync(202, "No storage allocation necessary."); return true;
                case "ABOR": await ReplyAsync(226, "No transfer to abort."); return true;
                case "STAT": await StatAsync(argument); return true;
                case "PWD" or "XPWD": await ReplyAsync(257, FtpReply.QuotePath(_cwd) + " is the current directory."); return true;
                case "CWD" or "XCWD": await CwdAsync(Resolve(argument)); return true;
                case "CDUP" or "XCUP": await CwdAsync(VirtualPath.GetParent(_cwd)); return true;
                case "MKD" or "XMKD": await MkdAsync(Resolve(argument)); return true;
                case "RMD" or "XRMD": await FileSystem.DeleteDirectoryAsync(Resolve(argument), Ct); await ReplyAsync(250, "Directory removed."); return true;
                case "DELE": await FileSystem.DeleteFileAsync(Resolve(argument), Ct); await ReplyAsync(250, "File deleted."); return true;
                case "RNFR": await RnfrAsync(Resolve(argument)); return true;
                case "RNTO": await RntoAsync(Resolve(argument)); return true;
                case "SIZE": await SizeAsync(Resolve(argument)); return true;
                case "MDTM": await MdtmAsync(Resolve(argument)); return true;
                case "REST": await RestAsync(argument); return true;
                case "SITE": await SiteAsync(argument); return true;
                case "PASV": await PasvAsync(); return true;
                case "EPSV": await EpsvAsync(argument); return true;
                case "PORT": await ActiveAsync(FtpAddresses.ParsePort(argument)); return true;
                case "EPRT": await ActiveAsync(FtpAddresses.ParseEprt(argument)); return true;
                case "LIST": await ListAsync(argument, FtpListKind.List); return true;
                case "NLST": await ListAsync(argument, FtpListKind.Names); return true;
                case "MLSD": await ListAsync(argument, FtpListKind.Machine); return true;
                case "MLST": await MlstAsync(Resolve(argument)); return true;
                case "RETR": await RetrAsync(Resolve(argument)); return true;
                case "STOR": await StoreAsync(Resolve(argument), append: false); return true;
                case "APPE": await StoreAsync(Resolve(argument), append: true); return true;
                default: await ReplyAsync(502, "Command not implemented."); return true;
            }
        }
        catch (FileSystemException ex)
        {
            var (code, text) = FtpErrors.Of(ex);
            await ReplyAsync(code, text);
            return true;
        }
    }

    /// <summary>The virtual path of an argument: absolute, or relative to the current directory. The storage normalizes it again.</summary>
    private string Resolve(string argument) =>
        VirtualPath.Normalize(argument.StartsWith('/') ? argument : VirtualPath.Combine(_cwd, argument));

    private string Features()
    {
        var lines = new List<string> { "Features:" };
        if (_options.Tls.Mode != FtpTlsMode.Disabled)
            lines.AddRange(["AUTH TLS", "PBSZ", "PROT"]);
        lines.AddRange(["EPSV", "PASV", "MDTM", "SIZE", "REST STREAM", "MLST " + FtpListing.MlstFacts, "UTF8", "TVFS", "CLNT"]);
        if (_options.AllowActiveMode)
            lines.Add("EPRT");
        lines.Add("End");
        return string.Join('\n', lines);
    }

    private async Task UserAsync(string username)
    {
        if (TlsRequired && !_channel.IsSecure)
        {
            await ReplyAsync(530, "This server needs FTPS: send AUTH TLS first.");
            return;
        }
        if (_user != null)
        {
            await ReplyAsync(503, "Already logged in.");
            return;
        }
        _pendingUser = username;
        await ReplyAsync(331, "Password required.");
    }

    private async Task<bool> PassAsync(string password)
    {
        if (TlsRequired && !_channel.IsSecure)
        {
            // The password is not checked: a sniffed password is not confirmed.
            await ReplyAsync(530, "This server needs FTPS: send AUTH TLS first.");
            return true;
        }
        if (_user != null)
        {
            await ReplyAsync(503, "Already logged in.");
            return true;
        }
        if (_pendingUser is not { } username)
        {
            await ReplyAsync(503, "Send USER first.");
            return true;
        }
        _pendingUser = null;

        var result = await _services.Login.LoginAsync(ConnectionProtocols.Ftp, UserProtocols.Ftp, username, password, _remote, Ct);
        switch (result.Status)
        {
            case PasswordLoginStatus.Ok:
                break;
            case PasswordLoginStatus.AddressRefused:
                await TryReplyAsync(421, "Access denied.");
                return false;
            case PasswordLoginStatus.ProtocolNotAllowed:
                await ReplyAsync(530, "FTP is not allowed for this user.");
                return true;
            default:
                if (++_failedLogins >= _options.MaxLoginAttempts)
                {
                    await TryReplyAsync(421, "Too many failed logins.");
                    return false;
                }
                await ReplyAsync(530, "Login incorrect.");
                return true;
        }

        var user = result.User!;
        if (!_services.Connections.TrySetAuthenticated(_connectionId, user.Username, result.Method!, user.MaxSessions))
        {
            var reason = UserLoginRules.SessionLimitReason(user.MaxSessions);
            _logger.LogInformation("The FTP login of {Username} from {RemoteEndPoint} is refused: {Reason}.", LogText.Clean(user.Username), _remoteEndPoint, reason);
            await _services.PublishAsync(new AuthEvent(AuthEventType.LoginFailed)
            {
                Timestamp = _services.Time.GetUtcNow(), Username = user.Username, RemoteIp = _remote.ToString(), Protocol = ConnectionProtocols.Ftp,
                Method = result.Method, Reason = reason, SessionId = _connectionId.ToString(),
            }, _logger);
            await ReplyAsync(530, "Too many sessions of the user.");
            return true;
        }

        try
        {
            _fileSystem = await _services.FileSystems.CreateAsync(user, new ClientContext(ConnectionProtocols.Ftp, _remote.ToString(), _connectionId), Ct);
        }
        catch (Exception ex) when (ex is ArgumentException or FileSystemException or KeyNotFoundException)
        {
            _logger.LogError(ex, "The storage of user {Username} cannot be created; the FTP login is refused.", LogText.Clean(user.Username));
            await TryReplyAsync(421, "The storage of the user is not available.");
            return false;
        }

        _user = user;
        _method = result.Method;
        await _services.PublishAsync(new AuthEvent(AuthEventType.LoginOk)
        {
            Timestamp = _services.Time.GetUtcNow(), Username = user.Username, RemoteIp = _remote.ToString(), Protocol = ConnectionProtocols.Ftp,
            Method = result.Method, SessionId = _connectionId.ToString(),
        }, _logger);
        SaveLastLogin(user.Username);
        await ReplyAsync(230, "Login successful.");
        return true;
    }

    private void SaveLastLogin(string username)
    {
        try
        {
            var stored = _services.Repository.GetUser(username);
            if (stored == null)
                return;
            stored.LastLoginAt = _services.Time.GetUtcNow().UtcDateTime;
            if (!_services.Repository.UpdateUser(stored))
                _logger.LogWarning("Could not save the last login time of user {Username}.", LogText.Clean(username));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not save the last login time of user {Username}.", LogText.Clean(username));
        }
    }

    private async Task<bool> AuthAsync(string argument)
    {
        var mechanism = argument.Trim().ToUpperInvariant();
        if (mechanism is not ("TLS" or "TLS-C" or "SSL"))
        {
            await ReplyAsync(504, "Only AUTH TLS is supported.");
            return true;
        }
        if (_services.Certificate.ServerOptions is not { } tls)
        {
            await ReplyAsync(502, "TLS is off on this server.");
            return true;
        }
        if (_channel.IsSecure || _user != null)
        {
            await ReplyAsync(503, _channel.IsSecure ? "TLS is on already." : "AUTH must come before the login.");
            return true;
        }

        await ReplyAsync(234, "AUTH TLS successful.");
        if (_channel.HasBufferedData)
        {
            // Commands sent in clear text after AUTH TLS would run as if they came over TLS (command injection).
            _logger.LogWarning("FTP connection {ConnectionId} sent data after AUTH TLS before the handshake; closing it.", _connectionId);
            return false;
        }
        try
        {
            await _channel.UpgradeToTlsAsync(tls, TimeSpan.FromSeconds(_options.DataTimeoutSeconds), Ct);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or OperationCanceledException && !Ct.IsCancellationRequested)
        {
            _logger.LogInformation("The TLS handshake of FTP connection {ConnectionId} from {RemoteEndPoint} failed: {Message}", _connectionId, _remoteEndPoint, ex.Message);
            return false;
        }
        _pendingUser = null;
        return true;
    }

    private async Task PbszAsync(string argument)
    {
        if (!_channel.IsSecure)
            await ReplyAsync(503, "Send AUTH TLS first.");
        else
            await ReplyAsync(200, "PBSZ=0");
    }

    private async Task ProtAsync(string argument)
    {
        if (!_channel.IsSecure)
        {
            await ReplyAsync(503, "Send AUTH TLS first.");
            return;
        }
        switch (argument.Trim().ToUpperInvariant())
        {
            case "P":
                _protectData = true;
                await ReplyAsync(200, "Data protection level set to Private.");
                break;
            case "C" when TlsRequired:
                await ReplyAsync(534, "This server needs protected data connections (PROT P).");
                break;
            case "C":
                _protectData = false;
                await ReplyAsync(200, "Data protection level set to Clear.");
                break;
            case "S" or "E":
                await ReplyAsync(536, "Only PROT C and PROT P are supported.");
                break;
            default:
                await ReplyAsync(504, "Unknown protection level.");
                break;
        }
    }

    private async Task OptsAsync(string argument)
    {
        var option = argument.Trim();
        if (option.Equals("UTF8 ON", StringComparison.OrdinalIgnoreCase) || option.Equals("UTF-8 ON", StringComparison.OrdinalIgnoreCase))
            await ReplyAsync(200, "UTF8 is always on.");
        else if (option.StartsWith("MLST", StringComparison.OrdinalIgnoreCase))
            await ReplyAsync(200, "MLST OPTS type;size;modify;");
        else
            await ReplyAsync(501, "Unknown option.");
    }

    private async Task TypeAsync(string argument)
    {
        switch (argument.Trim().ToUpperInvariant())
        {
            case "I" or "L 8" or "L8":
                await ReplyAsync(200, "Type set to I.");
                break;
            case "A" or "A N":
                // Files are sent as they are stored (no line end conversion), like most servers.
                await ReplyAsync(200, "Type set to A.");
                break;
            default:
                await ReplyAsync(504, "Only TYPE A and TYPE I are supported.");
                break;
        }
    }

    private async Task StatAsync(string argument)
    {
        if (argument.Trim().Length > 0)
        {
            await ReplyAsync(504, "STAT with a path is not supported; use LIST or MLST.");
            return;
        }
        await ReplyAsync(211, $"FreeSftpSharp FTP server status:\nConnected from {_remote}\n"
                              + (_user != null ? "Logged in as " + _user.Username + "\n" : "Not logged in\n")
                              + $"TLS on the control connection: {(_channel.IsSecure ? "yes" : "no")}\n"
                              + $"Data connections protected: {(_protectData ? "yes" : "no")}\nEnd of status.");
    }
}
