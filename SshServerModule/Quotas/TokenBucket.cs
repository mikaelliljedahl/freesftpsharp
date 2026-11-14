#nullable enable
using System;
using System.Threading;
using System.Threading.Tasks;

namespace SshServerModule.Quotas
{
    /// <summary>
    /// A token bucket for a byte rate (issue #62): it fills with <see cref="BytesPerSecond"/> up to its capacity, and a
    /// transfer takes its bytes from it. When the bucket is empty, the transfer goes into debt and waits until the debt is
    /// paid, so a request larger than the capacity works too and the average rate is the configured rate. The clock is a
    /// <see cref="TimeProvider"/>, so a test can drive it. Thread safe.
    /// </summary>
    public sealed class TokenBucket
    {
        private readonly TimeProvider _time;
        private readonly object _lock = new();
        private readonly double _capacity;
        private double _tokens;
        private long _last;

        /// <param name="bytesPerSecond">The rate, more than 0.</param>
        /// <param name="capacity">The bytes that can go at once after a pause. Null: a quarter of a second of the rate (at least 1 byte).</param>
        /// <param name="time">The clock. Null: the system clock.</param>
        public TokenBucket(long bytesPerSecond, long? capacity = null, TimeProvider? time = null)
        {
            if (bytesPerSecond <= 0)
                throw new ArgumentOutOfRangeException(nameof(bytesPerSecond), "The rate must be more than 0.");
            BytesPerSecond = bytesPerSecond;
            _capacity = Math.Max(1, capacity ?? bytesPerSecond / 4);
            _tokens = _capacity;
            _time = time ?? TimeProvider.System;
            _last = _time.GetTimestamp();
        }

        public long BytesPerSecond { get; }

        /// <summary>
        /// Takes <paramref name="bytes"/> from the bucket and completes when the rate allows them: at once while the bucket has
        /// tokens, else after the time that pays the debt.
        /// </summary>
        public ValueTask WaitAsync(long bytes, CancellationToken ct)
        {
            var delay = Take(bytes);
            return delay <= TimeSpan.Zero ? ValueTask.CompletedTask : new ValueTask(Task.Delay(delay, _time, ct));
        }

        /// <summary>Takes the bytes and returns how long the caller must wait for them.</summary>
        public TimeSpan Take(long bytes)
        {
            if (bytes <= 0)
                return TimeSpan.Zero;
            lock (_lock)
            {
                var now = _time.GetTimestamp();
                _tokens = Math.Min(_capacity, _tokens + _time.GetElapsedTime(_last, now).TotalSeconds * BytesPerSecond);
                _last = now;
                _tokens -= bytes;
                return _tokens >= 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(-_tokens / BytesPerSecond);
            }
        }
    }
}
