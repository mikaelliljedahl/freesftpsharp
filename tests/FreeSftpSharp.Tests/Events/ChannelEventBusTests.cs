using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Interfaces.Events;
using SshServerModule.Events;

namespace FreeSftpSharp.Tests.Events;

/// <summary>The event bus: fan-out to the sinks, isolation of the sinks, the bounded queue and the deny of the hooks.</summary>
public sealed class ChannelEventBusTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static ChannelEventBus CreateBus(IEnumerable<IEventSink> sinks, IEnumerable<IEventHook>? hooks = null, int capacity = ChannelEventBus.DefaultQueueCapacity)
        => new(sinks, hooks ?? [], NullLogger<ChannelEventBus>.Instance, capacity);

    private static SystemEvent Event(int number) => new(SystemEventType.ScheduledJobRan) { Message = number.ToString() };

    [Fact]
    public async Task Every_sink_gets_every_event_in_order()
    {
        var first = new RecordingEventSink();
        var second = new RecordingEventSink();
        await using var bus = CreateBus([first, second]);

        for (var i = 0; i < 100; i++)
            await bus.PublishAsync(Event(i), Ct);

        foreach (var sink in new[] { first, second })
        {
            var events = await sink.WaitForAsync<SystemEvent>(_ => true, 100);
            Assert.Equal(Enumerable.Range(0, 100).Select(i => i.ToString()), events.Select(e => e.Message));
        }
    }

    [Fact]
    public async Task A_throwing_sink_does_not_stop_the_other_sinks_and_is_counted()
    {
        var good = new RecordingEventSink();
        await using var bus = CreateBus([new ThrowingEventSink(), good]);

        await bus.PublishAsync(Event(1), Ct);
        await bus.PublishAsync(Event(2), Ct);

        await good.WaitForAsync<SystemEvent>(_ => true, 2);
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (bus.SinkFailures < 2 && DateTime.UtcNow < deadline)
            await Task.Delay(10, Ct);
        Assert.Equal(2, bus.SinkFailures);
    }

    [Fact]
    public async Task A_blocked_sink_does_not_delay_the_publisher_or_the_other_sinks()
    {
        var blocked = new BlockingEventSink();
        var good = new RecordingEventSink();
        await using var bus = CreateBus([blocked, good]);

        for (var i = 0; i < 50; i++)
        {
            var publish = bus.PublishAsync(Event(i), Ct);
            Assert.True(publish.IsCompletedSuccessfully, "PublishAsync waited although the queue had room.");
        }

        await good.WaitForAsync<SystemEvent>(_ => true, 50);
        Assert.Equal(0, blocked.Handled);
        blocked.Release();
    }

    [Fact]
    public async Task A_full_queue_makes_the_publisher_wait_and_drops_nothing()
    {
        var blocked = new BlockingEventSink();
        await using var bus = CreateBus([blocked], capacity: 2);

        await bus.PublishAsync(Event(1), Ct);
        await blocked.Entered; // the consumer holds event 1; the queue is empty again
        await bus.PublishAsync(Event(2), Ct);
        await bus.PublishAsync(Event(3), Ct);

        var fourth = bus.PublishAsync(Event(4), Ct).AsTask();
        await Task.Delay(100, Ct);
        Assert.False(fourth.IsCompleted, "The publisher did not wait for a full queue.");
        Assert.Equal(1, bus.PublisherWaits);

        blocked.Release();
        await fourth.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (blocked.Handled < 4 && DateTime.UtcNow < deadline)
            await Task.Delay(10, Ct);
        Assert.Equal(4, blocked.Handled);
    }

    [Fact]
    public async Task Dispose_delivers_the_queued_events()
    {
        var sink = new RecordingEventSink();
        var bus = CreateBus([sink]);
        for (var i = 0; i < 20; i++)
            await bus.PublishAsync(Event(i), Ct);

        await bus.DisposeAsync();

        Assert.Equal(20, sink.Events.Count);
    }

    [Fact]
    public async Task Without_hooks_an_operation_is_allowed()
    {
        await using var bus = CreateBus([]);

        var decision = await bus.AskAsync(new FileEvent(FileEventType.PreUpload), Ct);

        Assert.False(decision.IsDenied);
    }

    [Fact]
    public async Task The_first_deny_wins_and_the_later_hooks_are_not_asked()
    {
        var allow = new DelegateEventHook(_ => HookDecision.Allow);
        var deny = new DelegateEventHook(_ => HookDecision.Deny("no uploads today"));
        var later = new DelegateEventHook(_ => HookDecision.Allow);
        await using var bus = CreateBus([], [allow, deny, later]);

        var decision = await bus.AskAsync(new FileEvent(FileEventType.PreUpload), Ct);

        Assert.True(decision.IsDenied);
        Assert.Equal("no uploads today", decision.Message);
        Assert.Equal((1, 1, 0), (allow.Asked, deny.Asked, later.Asked));
    }

    [Fact]
    public async Task A_throwing_hook_denies_the_operation()
    {
        var throwing = new DelegateEventHook(_ => throw new InvalidOperationException("hook bug"));
        await using var bus = CreateBus([], [throwing]);

        var decision = await bus.AskAsync(new FileEvent(FileEventType.PreDelete), Ct);

        Assert.True(decision.IsDenied);
    }

    [Fact]
    public async Task Asking_does_not_publish_the_event()
    {
        var sink = new RecordingEventSink();
        var bus = CreateBus([sink], [new DelegateEventHook(_ => HookDecision.Allow)]);

        await bus.AskAsync(new FileEvent(FileEventType.PreUpload), Ct);
        await bus.DisposeAsync();

        Assert.Empty(sink.Events);
    }
}
