namespace FxSsh.Logging
{
    /// <summary>
    /// Configuration for <see cref="Log"/>. Process-wide, idempotent - call
    /// <see cref="Log.Configure"/> once at startup. Defaults to a silent
    /// <see cref="NullLogSink"/> at <see cref="LogLevel.Info"/> so the library
    /// is zero-overhead and no-op until the host opts in.
    /// </summary>
    public sealed class LogOptions
    {
        /// <summary>Minimum level that is written. Defaults to <see cref="LogLevel.Info"/>.</summary>
        public LogLevel MinLevel { get; set; } = LogLevel.Info;

        /// <summary>Output destination. Defaults to <see cref="NullLogSink"/> (silent).</summary>
        public ILogSink Sink { get; set; } = new NullLogSink();
    }
}
