using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.WebDav;

/// <summary>
/// A WebDAV session: the logins of one client with one credential, from one address, until it is idle for
/// <see cref="WebDavOptions.SessionIdleTimeoutSeconds"/>. HTTP sends the credentials with each request; the session
/// lets the server check the password once (a PBKDF2 key derivation) and gives the connection registry, the metrics and
/// the audit log one connection and one login instead of one per request.
/// </summary>
internal sealed class WebDavSession
{
    public WebDavSession(string key, Guid connectionId, User user, string userStamp, string method, IFileSystem fileSystem, DateTimeOffset now)
    {
        Key = key;
        ConnectionId = connectionId;
        User = user;
        UserStamp = userStamp;
        Method = method;
        FileSystem = fileSystem;
        _lastUsedTicks = now.UtcTicks;
    }

    public string Key { get; }
    public Guid ConnectionId { get; }
    public User User { get; }

    /// <summary>A hash of the stored user when the session started; another value means the user changed.</summary>
    public string UserStamp { get; }

    /// <summary>"password" or "app-password".</summary>
    public string Method { get; }

    /// <summary>The decorated file system of the user (permissions, events, connection tracking).</summary>
    public IFileSystem FileSystem { get; }

    private long _lastUsedTicks;

    public DateTimeOffset LastUsed => new(Interlocked.Read(ref _lastUsedTicks), TimeSpan.Zero);

    public void Touch(DateTimeOffset now) => Interlocked.Exchange(ref _lastUsedTicks, now.UtcTicks);
}

/// <summary>
/// The open WebDAV sessions. Each one is a connection in the <see cref="IConnectionRegistry"/> (protocol WebDAV) with a
/// <c>LoginOk</c> event at the start and a <c>Logout</c> event at the end. A session ends when it is idle
/// (<see cref="RemoveIdleAsync"/>), when an administrator disconnects it, or when the stored user changes.
/// </summary>
internal sealed class WebDavSessionStore
{
    private readonly ConcurrentDictionary<string, WebDavSession> _sessions = new(StringComparer.Ordinal);
    private readonly IConnectionRegistry _connections;
    private readonly IEventBus? _events;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly TimeSpan _idleTimeout;
    private readonly byte[] _keySecret = RandomNumberGenerator.GetBytes(32);

    public WebDavSessionStore(IConnectionRegistry connections, TimeProvider time, IOptions<WebDavOptions> options,
        ILogger<WebDavSessionStore> logger, IEventBus? events = null)
    {
        _connections = connections;
        _time = time;
        _logger = logger;
        _events = events;
        _idleTimeout = TimeSpan.FromSeconds(options.Value.SessionIdleTimeoutSeconds);
    }

    public int Count => _sessions.Count;

    /// <summary>
    /// The key of a session: the address and a keyed hash of the user name and password (the password is never kept;
    /// the key of the hash is random per process).
    /// </summary>
    public string KeyOf(string username, string password, IPAddress address)
    {
        var credential = HMACSHA256.HashData(_keySecret, Encoding.UTF8.GetBytes(username + "\0" + password));
        return Convert.ToBase64String(credential) + "|" + address;
    }

    /// <summary>
    /// The session with this key when it is still valid for <paramref name="storedUser"/> (the user as stored now). A
    /// session of a user that changed or was removed is ended, so the next request logs in again.
    /// </summary>
    public async ValueTask<WebDavSession?> FindAsync(string key, User? storedUser)
    {
        if (!_sessions.TryGetValue(key, out var session))
            return null;
        var now = _time.GetUtcNow();
        if (storedUser != null && now - session.LastUsed < _idleTimeout && StampOf(storedUser) == session.UserStamp)
        {
            session.Touch(now);
            _connections.RecordActivity(session.ConnectionId);
            return session;
        }
        await EndAsync(session, storedUser == null ? "the user was removed" : "the user changed or the session expired");
        return null;
    }

    /// <summary>Adds a new session, or returns the session that a parallel request of the same client added first.</summary>
    public async ValueTask<WebDavSession> AddAsync(WebDavSession session, string remoteIp)
    {
        var stored = _sessions.GetOrAdd(session.Key, session);
        if (!ReferenceEquals(stored, session))
        {
            _connections.Unregister(session.ConnectionId);
            return stored;
        }
        await PublishAsync(new AuthEvent(AuthEventType.LoginOk)
        {
            Timestamp = _time.GetUtcNow(), Username = session.User.Username, RemoteIp = remoteIp, Protocol = ConnectionProtocols.WebDav,
            Method = session.Method, SessionId = session.ConnectionId.ToString(),
        });
        return session;
    }

    /// <summary>Ends a session: removes it from the registry and publishes its <c>Logout</c>.</summary>
    public async ValueTask EndAsync(WebDavSession session, string reason)
    {
        if (!_sessions.TryRemove(new KeyValuePair<string, WebDavSession>(session.Key, session)))
            return;
        var info = _connections.Get(session.ConnectionId);
        _connections.Unregister(session.ConnectionId);
        _logger.LogInformation("WebDAV session {ConnectionId} of {Username} ended: {Reason}.", session.ConnectionId, session.User.Username, reason);
        await PublishAsync(new AuthEvent(AuthEventType.Logout)
        {
            Timestamp = _time.GetUtcNow(), Username = session.User.Username, RemoteIp = RemoteIpOf(info), Protocol = ConnectionProtocols.WebDav,
            Method = session.Method, SessionId = session.ConnectionId.ToString(),
        });
    }

    /// <summary>The session of a registry connection, for the disconnect callback of the registry.</summary>
    public WebDavSession? FindByConnection(Guid connectionId) => _sessions.Values.FirstOrDefault(s => s.ConnectionId == connectionId);

    /// <summary>Ends the sessions that had no request for the idle timeout.</summary>
    public async ValueTask<int> RemoveIdleAsync()
    {
        var now = _time.GetUtcNow();
        var ended = 0;
        foreach (var session in _sessions.Values.Where(s => now - s.LastUsed >= _idleTimeout).ToList())
        {
            await EndAsync(session, "idle");
            ended++;
        }
        return ended;
    }

    /// <summary>Ends every session (at the stop of the server).</summary>
    public async ValueTask EndAllAsync()
    {
        foreach (var session in _sessions.Values.ToList())
            await EndAsync(session, "the server stops");
    }

    /// <summary>A hash of everything stored for the user except the last login time (which the login itself changes).</summary>
    public static string StampOf(User user)
    {
        var node = JsonSerializer.SerializeToNode(user) as JsonObject ?? new JsonObject();
        node.Remove(nameof(User.LastSuccessfulLogin));
        return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    private static string? RemoteIpOf(ConnectionInfo? info)
    {
        if (info == null)
            return null;
        return IPEndPoint.TryParse(info.RemoteEndPoint, out var endPoint) ? endPoint.Address.ToString() : info.RemoteEndPoint;
    }

    private async ValueTask PublishAsync(IEvent @event)
    {
        if (_events == null)
            return;
        try
        {
            await _events.PublishAsync(@event, CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not publish the {Category} event {Type}.", @event.Category, @event.TypeName);
        }
    }
}
