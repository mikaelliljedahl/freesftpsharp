#nullable enable
using System;

namespace FxSsh.Logging
{
    /// <summary>
    /// Log output destination. Implementations are responsible for their own
    /// thread safety; the framework never blocks the hot path on a sink.
    /// </summary>
    public interface ILogSink
    {
        /// <summary>
        /// Write a single log entry.
        /// </summary>
        /// <param name="level">Severity of the entry.</param>
        /// <param name="message">Pre-formatted message. Never null.</param>
        /// <param name="exception">Optional exception to attach (Debug/Info levels usually pass null).</param>
        void Write(LogLevel level, string message, Exception? exception = null);
    }
}
