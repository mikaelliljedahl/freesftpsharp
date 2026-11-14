#nullable enable
namespace SshServerModule.Observability
{
    /// <summary>
    /// The names of the telemetry of the server. The core only produces <see cref="System.Diagnostics.Metrics.Meter"/> and
    /// <see cref="System.Diagnostics.ActivitySource"/> data; an exporter (OpenTelemetry, see SshServer.Observability) is opt-in
    /// and subscribes to these names. Without a listener the instruments cost almost nothing.
    /// </summary>
    public static class Telemetry
    {
        /// <summary>The name of the meter with all instruments of the server.</summary>
        public const string MeterName = "FreeSftpSharp";

        /// <summary>The name of the activity source (one activity per client session and per storage operation).</summary>
        public const string ActivitySourceName = "FreeSftpSharp";
    }
}
