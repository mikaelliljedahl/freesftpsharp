using Microsoft.Extensions.Logging;
using System;
using FxSshLog = FxSsh.Logging.Log;
using FxSshLogLevel = FxSsh.Logging.LogLevel;
using FxSshLogOptions = FxSsh.Logging.LogOptions;
using ILogSink = FxSsh.Logging.ILogSink;

namespace FxSsh.SshServerModule
{
    /// <summary>
    /// Sends the FxSsh library log (<see cref="FxSsh.Logging.Log"/>) to Microsoft.Extensions.Logging.
    /// The FxSsh log is static, so the last configured server wins.
    /// </summary>
    internal sealed class FxSshLogSink : ILogSink
    {
        private readonly ILogger _logger;

        private FxSshLogSink(ILogger logger)
        {
            _logger = logger;
        }

        internal static void Configure(ILogger logger)
        {
            FxSshLog.Configure(new FxSshLogOptions
            {
                MinLevel = MinimumLevel(logger),
                Sink = new FxSshLogSink(logger),
            });
        }

        public void Write(FxSshLogLevel level, string message, Exception exception = null)
        {
            _logger.Log(Map(level), exception, "FxSsh: {Message}", message);
        }

        internal static LogLevel Map(FxSshLogLevel level) => level switch
        {
            FxSshLogLevel.Trace => LogLevel.Trace,
            FxSshLogLevel.Debug => LogLevel.Debug,
            FxSshLogLevel.Info => LogLevel.Information,
            FxSshLogLevel.Warn => LogLevel.Warning,
            FxSshLogLevel.Fail => LogLevel.Error,
            _ => LogLevel.Critical,
        };

        // Let FxSsh skip building messages that the logger would drop anyway.
        private static FxSshLogLevel MinimumLevel(ILogger logger)
        {
            foreach (var level in new[] { FxSshLogLevel.Trace, FxSshLogLevel.Debug, FxSshLogLevel.Info, FxSshLogLevel.Warn, FxSshLogLevel.Fail })
            {
                if (logger.IsEnabled(Map(level)))
                    return level;
            }
            return FxSshLogLevel.Critical;
        }
    }
}
