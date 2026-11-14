using System.Collections.Concurrent;
using System.Diagnostics.Metrics;

namespace FreeSftpSharp.Tests.Observability;

/// <summary>A <see cref="MeterListener"/> on one <see cref="Meter"/> instance that keeps every measurement, for the tests.</summary>
public sealed class MeasurementCollector : IDisposable
{
    public sealed record Sample(string Instrument, double Value, IReadOnlyDictionary<string, object?> Tags);

    private readonly MeterListener _listener = new();
    private readonly ConcurrentQueue<Sample> _samples = new();

    public MeasurementCollector(Meter meter)
    {
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (ReferenceEquals(instrument.Meter, meter))
                listener.EnableMeasurementEvents(instrument);
        };
        _listener.SetMeasurementEventCallback<long>((i, v, tags, _) => Add(i, v, tags));
        _listener.SetMeasurementEventCallback<double>((i, v, tags, _) => Add(i, v, tags));
        _listener.Start();
    }

    private void Add(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        => _samples.Enqueue(new Sample(instrument.Name, value, tags.ToArray().ToDictionary(t => t.Key, t => t.Value)));

    /// <summary>Reads the observable instruments (gauges) now.</summary>
    public void Observe() => _listener.RecordObservableInstruments();

    public IReadOnlyList<Sample> Of(string instrument) => _samples.Where(s => s.Instrument == instrument).ToList();

    /// <summary>The sum of the measurements of <paramref name="instrument"/> with all of these tags.</summary>
    public double Sum(string instrument, params (string Key, string Value)[] tags)
        => Of(instrument).Where(s => tags.All(t => s.Tags.TryGetValue(t.Key, out var v) && (string?)v == t.Value)).Sum(s => s.Value);

    public void Dispose() => _listener.Dispose();
}
