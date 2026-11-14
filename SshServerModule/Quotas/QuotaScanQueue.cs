#nullable enable
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using SshServer.Interfaces.Quotas;

namespace SshServerModule.Quotas
{
    /// <summary>A queued scan: one scope, or every scope with a quota of a user (<see cref="Username"/>).</summary>
    public readonly record struct QuotaScanRequest(QuotaScope? Scope, string? Username);

    /// <summary>
    /// The queued quota scans (issue #62), read by <see cref="QuotaScanService"/>. It has no dependencies, so the storage
    /// factory, the provider events and the admin UI can queue a scan without a dependency cycle. A request that is already
    /// queued is not queued again.
    /// </summary>
    public sealed class QuotaScanQueue
    {
        private readonly Channel<QuotaScanRequest> _queue = Channel.CreateUnbounded<QuotaScanRequest>(new UnboundedChannelOptions { SingleReader = true });
        private readonly ConcurrentDictionary<QuotaScanRequest, byte> _pending = new();

        /// <summary>Queues a scan of the scope. False when it is already queued.</summary>
        public bool Request(QuotaScope scope) => Enqueue(new QuotaScanRequest(scope, null));

        /// <summary>Queues a scan of every scope with a disk quota of the user. False when it is already queued.</summary>
        public bool RequestUser(string username) => Enqueue(new QuotaScanRequest(null, username));

        /// <summary>True while a scan of the scope is queued and has not started.</summary>
        public bool IsPending(QuotaScope scope) => _pending.ContainsKey(new QuotaScanRequest(scope, null));

        /// <summary>True while a scan of every scope of the user is queued and has not started.</summary>
        public bool IsUserPending(string username) => _pending.ContainsKey(new QuotaScanRequest(null, username));

        /// <summary>The requests in order; each one leaves the pending set when it is read, so a new request during its scan is queued again.</summary>
        public async IAsyncEnumerable<QuotaScanRequest> ReadAllAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
        {
            await foreach (var request in _queue.Reader.ReadAllAsync(ct))
            {
                _pending.TryRemove(request, out _);
                yield return request;
            }
        }

        /// <summary>Takes the next request when one is queued (for tests and a synchronous drain).</summary>
        public bool TryRead(out QuotaScanRequest request)
        {
            if (!_queue.Reader.TryRead(out request))
                return false;
            _pending.TryRemove(request, out _);
            return true;
        }

        private bool Enqueue(QuotaScanRequest request) => _pending.TryAdd(request, 0) && _queue.Writer.TryWrite(request);
    }
}
