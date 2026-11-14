using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Shares;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The visitors of the share links (#70): one connection in the <see cref="IConnectionRegistry"/> per share and client
    /// address (protocol <see cref="ConnectionProtocols.HttpShare"/>, the owner as its user, method "share"), from the first
    /// request until <see cref="WebClientOptions.SessionIdleMinutes"/> without a request. So the admin page Connections shows
    /// it with its transfers and "Disconnect" ends it, and the chunks of one upload belong to one session
    /// (<see cref="UploadSessions"/>). A visitor does not count for the session limit of the owner. A session that ends
    /// aborts its unfinished uploads and publishes a <c>Logout</c> event. In memory and per node.
    /// </summary>
    public sealed class ShareSessions : IDisposable
    {
        public const string Method = "share";

        private sealed class Session
        {
            public required Guid Id { get; init; }
            public required string Username { get; init; }
            public required string RemoteIp { get; init; }
            public required string ShareId { get; init; }
            public long LastSeenTicks;
        }

        private readonly ConcurrentDictionary<(string Share, string Ip), Session> _sessions = new();
        private readonly ConcurrentDictionary<Guid, Session> _byConnection = new();
        private readonly object _lock = new();
        private readonly IConnectionRegistry _connections;
        private readonly IEventBus _events;
        private readonly UploadSessions _uploads;
        private readonly TimeProvider _time;
        private readonly WebClientOptions _options;
        private readonly ILogger<ShareSessions> _logger;

        public ShareSessions(IConnectionRegistry connections, IEventBus events, UploadSessions uploads, TimeProvider time,
            IOptions<WebClientOptions> options, ILogger<ShareSessions> logger)
        {
            _connections = connections;
            _events = events;
            _uploads = uploads;
            _time = time;
            _options = options.Value;
            _logger = logger;
            _connections.Changed += OnConnectionChanged;
        }

        /// <summary>The connection of the visitor of <paramref name="visit"/>: the open one, or a new one.</summary>
        public Guid Touch(ShareVisit visit)
        {
            var key = (visit.Share.Id, visit.RemoteIp);
            Session started = null;
            Session session;
            lock (_lock)
            {
                if (!_sessions.TryGetValue(key, out session) || _connections.Get(session.Id) == null)
                {
                    var connection = _connections.Register(new ConnectionRegistration(ConnectionProtocols.HttpShare, visit.RemoteIp, _ => Task.CompletedTask));
                    _connections.SetAuthenticated(connection.Id, visit.Owner.Username, Method);
                    session = new Session
                    {
                        Id = connection.Id,
                        Username = visit.Owner.Username,
                        RemoteIp = visit.RemoteIp,
                        ShareId = visit.Share.Id,
                        LastSeenTicks = _time.GetUtcNow().UtcTicks,
                    };
                    _sessions[key] = session;
                    _byConnection[session.Id] = session;
                    started = session;
                }
            }
            Interlocked.Exchange(ref session.LastSeenTicks, _time.GetUtcNow().UtcTicks);
            _connections.RecordActivity(session.Id);
            if (started != null)
                _ = PublishAsync(AuthEventType.LoginOk, started);
            return session.Id;
        }

        /// <summary>Ends the sessions without a request for <see cref="WebClientOptions.SessionIdleMinutes"/>. Returns how many.</summary>
        public int Sweep()
        {
            var limit = _time.GetUtcNow().UtcTicks - _options.SessionIdle.Ticks;
            var ended = 0;
            foreach (var session in _byConnection.Values)
            {
                if (Interlocked.Read(ref session.LastSeenTicks) >= limit)
                    continue;
                _connections.Unregister(session.Id);
                ended++;
            }
            return ended;
        }

        /// <summary>The open sessions (for the tests).</summary>
        public int Count => _byConnection.Count;

        private void OnConnectionChanged(ConnectionEvent change)
        {
            if (change.Kind != ConnectionEventKind.Disconnected || !_byConnection.TryRemove(change.Connection.Id, out var session))
                return;
            lock (_lock)
            {
                var key = (session.ShareId, session.RemoteIp);
                if (_sessions.TryGetValue(key, out var current) && current.Id == session.Id)
                    _sessions.TryRemove(key, out _);
            }
            _ = EndedAsync(session);
        }

        private async Task EndedAsync(Session session)
        {
            try
            {
                await _uploads.AbortSessionAsync(session.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "The uploads of the share session {SessionId} could not be aborted.", session.Id);
            }
            await PublishAsync(AuthEventType.Logout, session);
        }

        private async Task PublishAsync(AuthEventType type, Session session)
        {
            try
            {
                await _events.PublishAsync(new AuthEvent(type)
                {
                    Timestamp = _time.GetUtcNow(),
                    Username = session.Username,
                    RemoteIp = session.RemoteIp,
                    Protocol = ConnectionProtocols.HttpShare,
                    Method = Method + ":" + session.ShareId,
                    SessionId = session.Id.ToString(),
                }, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "The {Type} event of the share session {SessionId} could not be published.", type, session.Id);
            }
        }

        public void Dispose() => _connections.Changed -= OnConnectionChanged;
    }
}
