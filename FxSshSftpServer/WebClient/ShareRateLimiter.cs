using System;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;

namespace FxSshSftpServer.WebClient
{
    /// <summary>
    /// The rate limit of the share links (#70): <see cref="WebClientOptions.ShareRequestsPerMinute"/> requests per client
    /// address and minute on <c>/shares</c>, so share ids and passwords cannot be tried fast. More requests get 429.
    /// </summary>
    public sealed class ShareRateLimiter : IDisposable
    {
        private readonly PartitionedRateLimiter<string> _limiter;

        public ShareRateLimiter(IOptions<WebClientOptions> options)
        {
            var permits = options.Value.ShareRequestsPerMinute;
            _limiter = PartitionedRateLimiter.Create<string, string>(client => RateLimitPartition.GetFixedWindowLimiter(client, _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permits,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            }));
        }

        /// <summary>True when the client may make one more request now.</summary>
        public bool TryAcquire(string client)
        {
            using var lease = _limiter.AttemptAcquire(client ?? "(unknown)");
            return lease.IsAcquired;
        }

        public void Dispose() => _limiter.Dispose();
    }
}
