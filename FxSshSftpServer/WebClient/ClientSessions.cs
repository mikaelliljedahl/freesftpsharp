using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Net;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The browser sessions of the web client (#69). Each login is one connection in the <see cref="IConnectionRegistry"/>
    /// (protocol HTTP), so the admin UI shows it, the session limit of the user counts it, and "Disconnect" ends it. The
    /// registry is the store of the sessions: a cookie is valid only while its connection is registered. A session ends
    /// at logout, after <see cref="WebClientOptions.SessionIdleMinutes"/> without a request (<see cref="Sweep"/>), or when
    /// an administrator disconnects it; then its unfinished uploads are aborted and a logout event is published.
    /// In memory and per node, like the registry: with several nodes the browser needs sticky sessions.
    /// </summary>
    public sealed class ClientSessions : IDisposable
    {
        private sealed record Session(string Username, string Method, string RemoteIp, Security.Oidc.OidcSession Oidc)
        {
            public long LastSeenTicks;
        }

        private readonly IConnectionRegistry _connections;
        private readonly IEventBus _events;
        private readonly UploadSessions _uploads;
        private readonly TimeProvider _time;
        private readonly WebClientOptions _options;
        private readonly ILogger<ClientSessions> _logger;
        private readonly ConcurrentDictionary<Guid, Session> _sessions = new();

        public ClientSessions(IConnectionRegistry connections, IEventBus events, UploadSessions uploads, TimeProvider time,
            IOptions<WebClientOptions> options, ILogger<ClientSessions> logger)
        {
            _connections = connections;
            _events = events;
            _uploads = uploads;
            _time = time;
            _options = options.Value;
            _logger = logger;
            _connections.Changed += OnConnectionChanged;
        }

        /// <summary>
        /// Registers the session of a login and records the login. Null when the session limit of the user was reached
        /// at the same time by another login (the registry checks it in one step with the count). <paramref name="oidc"/> is
        /// the session at the identity provider of an OpenID Connect sign-in, for its back-channel logout (#145).
        /// </summary>
        public Guid? Start(User user, string method, IPAddress remoteIp, int remotePort, Security.Oidc.OidcSession oidc = null)
        {
            var ip = remoteIp == null ? "?" : CidrNotation.Normalize(remoteIp).ToString();
            var endPoint = remoteIp == null ? "?" : new IPEndPoint(CidrNotation.Normalize(remoteIp), remotePort).ToString();
            // The registry removes the entry after the callback; the Changed event does the rest (OnConnectionChanged).
            var connection = _connections.Register(new ConnectionRegistration(ClientAuth.Protocol, endPoint, _ => Task.CompletedTask));
            _sessions[connection.Id] = new Session(user.Username, method, ip, oidc) { LastSeenTicks = _time.GetUtcNow().UtcTicks };
            if (!_connections.TrySetAuthenticated(connection.Id, user.Username, method, user.MaxSessions))
            {
                _sessions.TryRemove(connection.Id, out _);
                _connections.Unregister(connection.Id);
                return null;
            }
            return connection.Id;
        }

        /// <summary>
        /// True when <paramref name="id"/> is an open session of <paramref name="username"/>; records the request as
        /// activity. False for a session that ended (logout, idle, disconnected by an administrator).
        /// </summary>
        public bool Touch(Guid id, string username)
        {
            if (!_sessions.TryGetValue(id, out var session) || !string.Equals(session.Username, username, StringComparison.OrdinalIgnoreCase))
                return false;
            var connection = _connections.Get(id);
            if (connection == null || connection.Protocol != ClientAuth.Protocol)
                return false;
            Interlocked.Exchange(ref session.LastSeenTicks, _time.GetUtcNow().UtcTicks);
            _connections.RecordActivity(id);
            return true;
        }

        /// <summary>Ends a session (logout, or a login that is not valid any more).</summary>
        public void End(Guid id) => _connections.Unregister(id);

        /// <summary>Ends every browser session of the user except <paramref name="keep"/> (after a new password).</summary>
        public void EndOthers(string username, Guid keep)
        {
            foreach (var (id, session) in _sessions)
            {
                if (id != keep && string.Equals(session.Username, username, StringComparison.OrdinalIgnoreCase))
                    End(id);
            }
        }

        /// <summary>
        /// Ends the sessions of the OpenID Connect sign-ins that a back-channel logout of the identity provider ended (#145):
        /// the same sid, or without a sid in the logout, the same subject. Returns how many.
        /// </summary>
        public int EndOidc(Security.Oidc.OidcLogout logout)
        {
            ArgumentNullException.ThrowIfNull(logout);
            var ended = 0;
            foreach (var (id, session) in _sessions)
            {
                if (session.Oidc == null || !session.Oidc.IsEndedBy(logout))
                    continue;
                _logger.LogInformation("The web client session {SessionId} of {Username} ended by a logout at the identity provider.", id, session.Username);
                End(id);
                ended++;
            }
            return ended;
        }

        /// <summary>Ends the sessions without a request for <see cref="WebClientOptions.SessionIdleMinutes"/>. Returns how many.</summary>
        public int Sweep()
        {
            var limit = _time.GetUtcNow().UtcTicks - _options.SessionIdle.Ticks;
            var ended = 0;
            foreach (var (id, session) in _sessions)
            {
                if (Interlocked.Read(ref session.LastSeenTicks) >= limit)
                    continue;
                _logger.LogInformation("The web client session {SessionId} of {Username} ended after {Minutes} minutes without a request.",
                    id, session.Username, _options.SessionIdleMinutes);
                End(id);
                ended++;
            }
            return ended;
        }

        private void OnConnectionChanged(ConnectionEvent change)
        {
            if (change.Kind != ConnectionEventKind.Disconnected || !_sessions.TryRemove(change.Connection.Id, out var session))
                return;
            var id = change.Connection.Id;
            _ = EndedAsync(id, session);
        }

        private async Task EndedAsync(Guid id, Session session)
        {
            try
            {
                await _uploads.AbortSessionAsync(id);
                await _events.PublishAsync(new AuthEvent(AuthEventType.Logout)
                {
                    Timestamp = _time.GetUtcNow(),
                    Username = session.Username,
                    RemoteIp = session.RemoteIp,
                    Protocol = ClientAuth.Protocol,
                    Method = session.Method,
                    SessionId = id.ToString(),
                }, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "The end of the web client session {SessionId} of {Username} could not be completed.", id, session.Username);
            }
        }

        public void Dispose() => _connections.Changed -= OnConnectionChanged;
    }
}
