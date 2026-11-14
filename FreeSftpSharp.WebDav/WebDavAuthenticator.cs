using System.Net;
using System.Text;
using FxSsh.SshServerModule.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Net;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.Users;

namespace FreeSftpSharp.WebDav;

/// <summary>
/// The login of a WebDAV request: HTTP Basic (RFC 7617), only over HTTPS or from loopback (or with
/// <see cref="WebDavOptions.AllowInsecureHttp"/>), through the <see cref="PasswordLoginService"/> (the same rules as the
/// SFTP login, the auto-ban and the app passwords), and the <see cref="WebDavSessionStore"/>. Digest is not implemented.
/// </summary>
internal sealed class WebDavAuthenticator
{
    private readonly PasswordLoginService _login;
    private readonly WebDavSessionStore _sessions;
    private readonly ISettingsRepository _repository;
    private readonly IFileSystemFactory _fileSystems;
    private readonly IConnectionRegistry _connections;
    private readonly WebDavOptions _options;
    private readonly ILogger _logger;

    public WebDavAuthenticator(PasswordLoginService login, WebDavSessionStore sessions, ISettingsRepository repository,
        IFileSystemFactory fileSystems, IConnectionRegistry connections, IOptions<WebDavOptions> options, ILogger<WebDavAuthenticator> logger)
    {
        _login = login;
        _sessions = sessions;
        _repository = repository;
        _fileSystems = fileSystems;
        _connections = connections;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>The session of the request, or null when the response (401 or 403) is written.</summary>
    public async ValueTask<WebDavSession?> AuthenticateAsync(HttpContext context)
    {
        var remote = context.Connection.RemoteIpAddress;
        if (remote == null)
        {
            await WriteForbiddenAsync(context, "The client address is unknown.");
            return null;
        }
        remote = CidrNotation.Normalize(remote);

        if (_login.CheckAddress(remote) != IpFilterResult.Allowed)
        {
            await WriteForbiddenAsync(context, "Access denied.");
            return null;
        }

        // The credentials are not even read on plain HTTP: they are not checked, so a sniffed password is not confirmed.
        if (!context.Request.IsHttps && !IPAddress.IsLoopback(remote) && !_options.AllowInsecureHttp)
        {
            await WriteForbiddenAsync(context, "WebDAV needs HTTPS.");
            return null;
        }

        if (!TryReadBasic(context.Request, out var username, out var password))
        {
            Challenge(context);
            return null;
        }

        var key = _sessions.KeyOf(username, password, remote);
        var stored = _repository.GetUser(username);
        var session = await _sessions.FindAsync(key, stored);
        if (session != null)
            return session;

        var result = await _login.LoginAsync(ConnectionProtocols.WebDav, UserProtocols.WebDav, username, password, remote, context.RequestAborted);
        switch (result.Status)
        {
            case PasswordLoginStatus.Ok:
                break;
            case PasswordLoginStatus.Failed:
                Challenge(context);
                return null;
            case PasswordLoginStatus.ProtocolNotAllowed:
                await WriteForbiddenAsync(context, "WebDAV is not allowed for this user.");
                return null;
            default:
                await WriteForbiddenAsync(context, "Access denied.");
                return null;
        }

        var user = result.User!;
        var stamp = _sessions.StampOf(user);
        var remoteEndPoint = new IPEndPoint(remote, context.Connection.RemotePort).ToString();
        WebDavSession? created = null;
        var connection = _connections.Register(new ConnectionRegistration(ConnectionProtocols.WebDav, remoteEndPoint, async reason =>
        {
            if (created != null)
                await _sessions.EndAsync(created, "disconnected by an administrator: " + reason);
        }));
        try
        {
            if (context.Request.Headers.UserAgent.ToString() is { Length: > 0 } agent)
                _connections.SetClientVersion(connection.Id, agent);
            if (!_connections.TrySetAuthenticated(connection.Id, user.Username, result.Method!, user.MaxSessions))
            {
                // The session limit of the user (#61): the open WebDAV and SFTP sessions count.
                _connections.Unregister(connection.Id);
                await _sessions.PublishLoginFailedAsync(user.Username, remote.ToString(), result.Method!, UserLoginRules.SessionLimitReason(user.MaxSessions));
                await WriteForbiddenAsync(context, "Too many sessions of the user.");
                return null;
            }
            var fileSystem = await _fileSystems.CreateAsync(user, new ClientContext(ConnectionProtocols.WebDav, remote.ToString(), connection.Id),
                context.RequestAborted);
            created = new WebDavSession(key, connection.Id, user, stamp, result.Method!, fileSystem, _login.Time.GetUtcNow());
        }
        catch (Exception ex) when (ex is ArgumentException or FileSystemException or KeyNotFoundException)
        {
            _connections.Unregister(connection.Id);
            _logger.LogError(ex, "The storage of user {Username} cannot be created; the WebDAV request is refused.", LogText.Clean(user.Username));
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            return null;
        }
        catch
        {
            _connections.Unregister(connection.Id);
            throw;
        }

        var added = await _sessions.AddAsync(created, remote.ToString());
        if (ReferenceEquals(added, created))
            SaveLastLogin(user.Username);
        return added;
    }

    private void SaveLastLogin(string username)
    {
        try
        {
            var user = _repository.GetUser(username);
            if (user == null)
                return;
            user.LastLoginAt = _login.Time.GetUtcNow().UtcDateTime;
            if (!_repository.UpdateUser(user))
                _logger.LogWarning("Could not save the last login time of user {Username}.", LogText.Clean(username));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not save the last login time of user {Username}.", LogText.Clean(username));
        }
    }

    /// <summary>Reads "Authorization: Basic base64(user:password)" (UTF-8, RFC 7617).</summary>
    internal static bool TryReadBasic(HttpRequest request, out string username, out string password)
    {
        username = password = string.Empty;
        var header = request.Headers.Authorization.ToString();
        if (!header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            return false;
        string decoded;
        try
        {
            decoded = new UTF8Encoding(false, true).GetString(Convert.FromBase64String(header[6..].Trim()));
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            return false;
        }
        var colon = decoded.IndexOf(':');
        if (colon <= 0)
            return false;
        username = decoded[..colon];
        password = decoded[(colon + 1)..];
        return true;
    }

    private void Challenge(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.WWWAuthenticate = $"Basic realm=\"{_options.Realm}\", charset=\"UTF-8\"";
    }

    private static async Task WriteForbiddenAsync(HttpContext context, string message)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "text/plain; charset=utf-8";
        await context.Response.WriteAsync(message, context.RequestAborted);
    }
}
