#nullable enable
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;

namespace SshServerModule.Observability
{
    /// <summary>
    /// The instruments of the server (meter <see cref="Telemetry.MeterName"/>), and the trace activities of the client
    /// sessions and storage operations (<see cref="Telemetry.ActivitySourceName"/>). It is fed from two places only: the
    /// <see cref="IConnectionRegistry"/> (connections) and, as an <see cref="IEventSink"/>, the event bus (logins and
    /// transfers). No protocol and no storage backend knows about it.
    /// <list type="bullet">
    /// <item><c>freesftpsharp.connections.active</c> {protocol}: open connections (gauge, read from the registry).</item>
    /// <item><c>freesftpsharp.connections</c> {protocol}: accepted connections (counter).</item>
    /// <item><c>freesftpsharp.auth.attempts</c> {method,result}: logins, result "ok" or "failed".</item>
    /// <item><c>freesftpsharp.transfers</c> {protocol,direction,status}: finished transfers, status "ok", "error", ...</item>
    /// <item><c>freesftpsharp.transfer.bytes</c> {protocol,direction}: bytes of the successful transfers.</item>
    /// <item><c>freesftpsharp.transfer.duration</c> {protocol,direction} (seconds): time of the transfers.</item>
    /// <item><c>freesftpsharp.storage.operation.duration</c> {provider,operation} (seconds).</item>
    /// <item><c>freesftpsharp.storage.errors</c> {provider,error}: file operations that failed.</item>
    /// </list>
    /// A Prometheus exporter shows them as, for example, <c>freesftpsharp_transfers_total</c>.
    /// </summary>
    public sealed class FreeSftpSharpMetrics : IEventSink, IDisposable
    {
        private static readonly ActivitySource Source = new(Telemetry.ActivitySourceName);

        private readonly IConnectionRegistry _registry;
        private readonly Meter _meter = new(Telemetry.MeterName);
        private readonly Counter<long> _connections;
        private readonly Counter<long> _auth;
        private readonly Counter<long> _transfers;
        private readonly Counter<long> _transferBytes;
        private readonly Histogram<double> _transferDuration;
        private readonly Histogram<double> _storageDuration;
        private readonly Counter<long> _storageErrors;
        private readonly ConcurrentDictionary<string, Activity> _sessions = new();

        public FreeSftpSharpMetrics(IConnectionRegistry registry)
        {
            _registry = registry ?? throw new ArgumentNullException(nameof(registry));
            _meter.CreateObservableGauge("freesftpsharp.connections.active", ObserveActive, "{connection}", "Open client connections.");
            _connections = _meter.CreateCounter<long>("freesftpsharp.connections", "{connection}", "Accepted client connections.");
            _auth = _meter.CreateCounter<long>("freesftpsharp.auth.attempts", "{attempt}", "Login attempts by method and result.");
            _transfers = _meter.CreateCounter<long>("freesftpsharp.transfers", "{transfer}", "Finished file transfers.");
            _transferBytes = _meter.CreateCounter<long>("freesftpsharp.transfer.bytes", "By", "Bytes of the successful file transfers.");
            _transferDuration = _meter.CreateHistogram<double>("freesftpsharp.transfer.duration", "s", "Time from the open to the close of a transfer.");
            _storageDuration = _meter.CreateHistogram<double>("freesftpsharp.storage.operation.duration", "s", "Time of a storage operation.");
            _storageErrors = _meter.CreateCounter<long>("freesftpsharp.storage.errors", "{error}", "File operations that failed.");
            _registry.Changed += OnConnectionChanged;
        }

        /// <summary>The meter. The tests use it to listen to this instance only.</summary>
        public Meter Meter => _meter;

        private IEnumerable<Measurement<long>> ObserveActive()
        {
            foreach (var group in _registry.GetAll().GroupBy(c => c.Protocol))
                yield return new Measurement<long>(group.Count(), new KeyValuePair<string, object?>("protocol", group.Key));
        }

        private void OnConnectionChanged(ConnectionEvent change)
        {
            var id = change.Connection.Id.ToString();
            switch (change.Kind)
            {
                case ConnectionEventKind.Connected:
                    _connections.Add(1, new KeyValuePair<string, object?>("protocol", change.Connection.Protocol));
                    var activity = Source.StartActivity("sftp.session", ActivityKind.Server);
                    if (activity != null)
                    {
                        activity.SetTag("freesftpsharp.protocol", change.Connection.Protocol);
                        activity.SetTag("freesftpsharp.connection_id", id);
                        _sessions[id] = activity;
                    }
                    break;
                case ConnectionEventKind.Authenticated:
                    if (_sessions.TryGetValue(id, out var session))
                    {
                        session.SetTag("enduser.id", change.Connection.Username);
                        session.SetTag("freesftpsharp.auth_method", change.Connection.AuthMethod);
                    }
                    break;
                case ConnectionEventKind.Disconnected:
                    if (_sessions.TryRemove(id, out var ended))
                        ended.Dispose();
                    break;
            }
        }

        public ValueTask HandleAsync(IEvent @event, CancellationToken ct)
        {
            switch (@event)
            {
                case AuthEvent { Type: AuthEventType.LoginOk or AuthEventType.LoginFailed } auth:
                    _auth.Add(1,
                        new KeyValuePair<string, object?>("method", auth.Method ?? "unknown"),
                        new KeyValuePair<string, object?>("result", auth.Type == AuthEventType.LoginOk ? "ok" : "failed"));
                    break;
                case FileEvent file when !file.IsPreEvent && file.Type != FileEventType.FirstUpload && file.Status != FileEventStatus.Denied:
                    CountFile(file);
                    break;
            }
            return ValueTask.CompletedTask;
        }

        private void CountFile(FileEvent file)
        {
            var provider = file.Provider ?? "unknown";
            var operation = file.Type.ToString().ToLowerInvariant();
            if (file.Type is FileEventType.Upload or FileEventType.Download)
            {
                var direction = file.Type == FileEventType.Upload ? "upload" : "download";
                var protocol = file.Protocol;
                _transfers.Add(1,
                    new KeyValuePair<string, object?>("protocol", protocol),
                    new KeyValuePair<string, object?>("direction", direction),
                    new KeyValuePair<string, object?>("status", file.Status.ToString().ToLowerInvariant()));
                if (file.Status == FileEventStatus.Ok)
                {
                    if (file.FileSize is { } size)
                        _transferBytes.Add(size,
                            new KeyValuePair<string, object?>("protocol", protocol),
                            new KeyValuePair<string, object?>("direction", direction));
                    if (file.Elapsed is { } took)
                        _transferDuration.Record(took.TotalSeconds,
                            new KeyValuePair<string, object?>("protocol", protocol),
                            new KeyValuePair<string, object?>("direction", direction));
                }
            }

            if (file.Elapsed is { } elapsed)
                _storageDuration.Record(elapsed.TotalSeconds,
                    new KeyValuePair<string, object?>("provider", provider),
                    new KeyValuePair<string, object?>("operation", operation));
            if (file.Status is FileEventStatus.Error or FileEventStatus.QuotaExceeded)
                _storageErrors.Add(1,
                    new KeyValuePair<string, object?>("provider", provider),
                    new KeyValuePair<string, object?>("error", file.Status.ToString().ToLowerInvariant()));

            TraceOperation(file, operation, provider);
        }

        /// <summary>One activity for the operation, under the activity of the session; it starts where the operation started.</summary>
        private void TraceOperation(FileEvent file, string operation, string provider)
        {
            if (!Source.HasListeners() || file.Elapsed is not { } elapsed)
                return;

            var parent = file.SessionId != null && _sessions.TryGetValue(file.SessionId, out var session) ? session.Context : default;
            var end = file.Timestamp == default ? DateTimeOffset.UtcNow : file.Timestamp;
            using var activity = Source.StartActivity("storage." + operation, ActivityKind.Internal, parent,
                startTime: end - elapsed);
            if (activity == null)
                return;
            activity.SetTag("freesftpsharp.provider", provider);
            activity.SetTag("freesftpsharp.operation", operation);
            activity.SetTag("freesftpsharp.status", file.Status.ToString());
            if (file.FileSize is { } size)
                activity.SetTag("freesftpsharp.bytes", size);
            if (file.Status != FileEventStatus.Ok)
                activity.SetStatus(ActivityStatusCode.Error, file.Message);
            activity.SetEndTime(end.UtcDateTime);
        }

        public void Dispose()
        {
            _registry.Changed -= OnConnectionChanged;
            foreach (var key in _sessions.Keys.ToArray())
                if (_sessions.TryRemove(key, out var activity))
                    activity.Dispose();
            _meter.Dispose();
        }
    }
}
