#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Events;

namespace SshServerModule.Events
{
    /// <summary>
    /// <see cref="IEventBus"/> on <see cref="System.Threading.Channels"/>. Every <see cref="IEventSink"/> has its own
    /// bounded queue and one consumer task, so a sink that is slow, blocks or throws delays only itself: the
    /// publisher and the other sinks go on. Back pressure drops nothing: when the queue of a sink is full, the
    /// publisher waits for space; <see cref="PublisherWaits"/> (metric <c>freesftpsharp.events.publisher_waits</c>)
    /// counts these waits.
    /// <para>
    /// Dispose stops the bus: the queued events are given to the sinks for at most <see cref="DrainTimeout"/>, then
    /// the sinks are canceled.
    /// </para>
    /// </summary>
    public sealed class ChannelEventBus : IEventBus, IAsyncDisposable, IDisposable
    {
        public const int DefaultQueueCapacity = 10_000;
        public const string MeterName = "FreeSftpSharp.Events";
        internal static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(5);

        private readonly ILogger _logger;
        private readonly IEventHook[] _hooks;
        private readonly SinkWorker[] _workers;
        private readonly CancellationTokenSource _stopping = new();
        private readonly Meter _meter = new(MeterName);
        private readonly Counter<long> _publishedCounter;
        private readonly Counter<long> _waitCounter;
        private readonly Counter<long> _failureCounter;
        private long _publisherWaits;
        private long _sinkFailures;
        private int _disposed;

        public ChannelEventBus(IEnumerable<IEventSink> sinks, IEnumerable<IEventHook> hooks, ILogger<ChannelEventBus> logger,
            int queueCapacity = DefaultQueueCapacity)
        {
            if (queueCapacity < 1)
                throw new ArgumentOutOfRangeException(nameof(queueCapacity), "The queue needs room for at least one event.");
            _logger = logger;
            _hooks = hooks.ToArray();
            _publishedCounter = _meter.CreateCounter<long>("freesftpsharp.events.published", description: "Events published on the event bus.");
            _waitCounter = _meter.CreateCounter<long>("freesftpsharp.events.publisher_waits",
                description: "Publishes that waited because the queue of a sink was full.");
            _failureCounter = _meter.CreateCounter<long>("freesftpsharp.events.sink_failures", description: "Events that a sink failed to handle.");
            _workers = sinks.Select(sink => new SinkWorker(this, sink, queueCapacity)).ToArray();
        }

        /// <summary>How many times a publisher had to wait because the queue of a sink was full.</summary>
        public long PublisherWaits => Interlocked.Read(ref _publisherWaits);

        /// <summary>How many events a sink failed to handle (threw).</summary>
        public long SinkFailures => Interlocked.Read(ref _sinkFailures);

        public async ValueTask PublishAsync(IEvent @event, CancellationToken ct = default)
        {
            ArgumentNullException.ThrowIfNull(@event);
            if (Volatile.Read(ref _disposed) != 0)
            {
                _logger.LogDebug("The event bus is stopped; the {Category} event {Type} is not delivered.", @event.Category, @event.TypeName);
                return;
            }

            _publishedCounter.Add(1);
            foreach (var worker in _workers)
            {
                if (worker.Writer.TryWrite(@event))
                    continue;

                var waits = Interlocked.Increment(ref _publisherWaits);
                _waitCounter.Add(1);
                if (waits % 1000 == 1) // the first wait and then every 1000th, not a line per event
                    _logger.LogWarning("The event queue of {Sink} is full; the publisher waits ({Waits} waits so far).", worker.Name, waits);
                try
                {
                    await worker.Writer.WriteAsync(@event, ct);
                }
                catch (ChannelClosedException)
                {
                    // Stopped while waiting.
                }
            }
        }

        public async Task<HookDecision> AskAsync(IEvent @event, CancellationToken ct = default)
        {
            ArgumentNullException.ThrowIfNull(@event);
            foreach (var hook in _hooks)
            {
                HookDecision decision;
                try
                {
                    decision = await hook.DecideAsync(@event, ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "The event hook {Hook} failed on {Type}; the operation is refused.", hook.GetType().Name, @event.TypeName);
                    return HookDecision.Deny($"The event hook {hook.GetType().Name} failed.");
                }

                if (decision.IsDenied)
                {
                    _logger.LogInformation("The event hook {Hook} refused {Type}: {Reason}", hook.GetType().Name, @event.TypeName, decision.Message);
                    return decision;
                }
            }
            return HookDecision.Allow;
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;

            foreach (var worker in _workers)
                worker.Writer.TryComplete();
            var all = Task.WhenAll(_workers.Select(w => w.Completion));
            try
            {
                await all.WaitAsync(DrainTimeout);
            }
            catch (TimeoutException)
            {
                _logger.LogWarning("The event sinks did not finish within {Seconds} s; they are canceled.", DrainTimeout.TotalSeconds);
            }
            _stopping.Cancel(); // not disposed: a sink that ignores the cancellation can still read the token
            _meter.Dispose();
        }

        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

        private void OnSinkFailed(string sink, IEvent @event, Exception ex)
        {
            Interlocked.Increment(ref _sinkFailures);
            _failureCounter.Add(1);
            _logger.LogError(ex, "The event sink {Sink} failed on the {Category} event {Type}.", sink, @event.Category, @event.TypeName);
        }

        /// <summary>The queue and the consumer task of one sink.</summary>
        private sealed class SinkWorker
        {
            private readonly ChannelEventBus _bus;
            private readonly IEventSink _sink;
            private readonly Channel<IEvent> _queue;
            private readonly CancellationToken _token;

            public SinkWorker(ChannelEventBus bus, IEventSink sink, int capacity)
            {
                _bus = bus;
                _token = bus._stopping.Token;
                _sink = sink;
                Name = sink.GetType().Name;
                _queue = Channel.CreateBounded<IEvent>(new BoundedChannelOptions(capacity)
                {
                    FullMode = BoundedChannelFullMode.Wait,
                    SingleReader = true,
                    SingleWriter = false,
                });
                // Task.Run: a sink that blocks synchronously must not block the constructor or a publisher.
                Completion = Task.Run(ConsumeAsync);
            }

            public string Name { get; }

            public ChannelWriter<IEvent> Writer => _queue.Writer;

            public Task Completion { get; }

            private async Task ConsumeAsync()
            {
                var token = _token;
                try
                {
                    await foreach (var @event in _queue.Reader.ReadAllAsync(token))
                    {
                        try
                        {
                            await _sink.HandleAsync(@event, token);
                        }
                        catch (OperationCanceledException) when (token.IsCancellationRequested)
                        {
                            return;
                        }
                        catch (Exception ex)
                        {
                            _bus.OnSinkFailed(Name, @event, ex);
                        }
                    }
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    // Stopped.
                }
            }
        }
    }
}
