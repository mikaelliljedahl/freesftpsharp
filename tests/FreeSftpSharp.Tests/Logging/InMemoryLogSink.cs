using Serilog;
using Serilog.Configuration;
using Serilog.Core;
using Serilog.Events;

namespace FreeSftpSharp.Tests.Logging;

/// <summary>Collects Serilog events in memory. The web host test adds it through the Serilog configuration.</summary>
public sealed class InMemoryLogSink : ILogEventSink
{
    public static InMemoryLogSink Instance { get; } = new();

    private readonly List<LogEvent> _events = new();

    public IReadOnlyList<LogEvent> Snapshot()
    {
        lock (_events) return _events.ToList();
    }

    public void Clear()
    {
        lock (_events) _events.Clear();
    }

    public void Emit(LogEvent logEvent)
    {
        lock (_events) _events.Add(logEvent);
    }
}

public static class InMemoryLogSinkExtensions
{
    /// <summary>Used as <c>"Name": "InMemoryLog"</c> with <c>"Using": ["FreeSftpSharp.Tests"]</c>.</summary>
    public static LoggerConfiguration InMemoryLog(this LoggerSinkConfiguration sinks) => sinks.Sink(InMemoryLogSink.Instance);
}
