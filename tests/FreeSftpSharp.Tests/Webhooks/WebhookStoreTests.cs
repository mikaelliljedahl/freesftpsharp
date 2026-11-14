using SshServer.Interfaces.Admins;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Webhooks;
using SshServer.Webhooks;

namespace FreeSftpSharp.Tests.Webhooks;

/// <summary>The SQLite store and the admin service: leases for several nodes, unique names, the secret encrypted at rest.</summary>
public sealed class WebhookStoreTests : IAsyncLifetime
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly DateTime Now = new(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);
    private const string Secret = "plain-secret-must-not-be-stored-0123";

    private readonly RecordingSink _events = new();
    private WebhookTestHost _host = null!;

    public ValueTask InitializeAsync()
    {
        _host = new WebhookTestHost(configure: s => s.AddSingleton<IEventSink>(_events));
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    /// <summary>
    /// Records the events on the consumer task of its queue of the event bus; the test reads them on another thread, so the
    /// list is only read as a snapshot under the lock, and the test waits for an event with a signal, not with a poll.
    /// </summary>
    private sealed class RecordingSink : IEventSink
    {
        private readonly List<IEvent> _events = [];
        private readonly TaskCompletionSource _systemEvent = new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>The events so far (a copy).</summary>
        public IReadOnlyList<IEvent> Events
        {
            get
            {
                lock (_events)
                    return [.. _events];
            }
        }

        /// <summary>Completes when a <see cref="SystemEvent"/> is here; the queue is in order, so every event before it is here too.</summary>
        public Task SystemEventSeen => _systemEvent.Task;

        public ValueTask HandleAsync(IEvent @event, CancellationToken ct)
        {
            lock (_events)
                _events.Add(@event);
            if (@event is SystemEvent)
                _systemEvent.TrySetResult();
            return ValueTask.CompletedTask;
        }
    }

    private Task<int> AddAsync(string name = "hook") => _host.AddWebhookAsync(new WebhookInput
    {
        Name = name, Url = "https://hooks.example.com/" + name, NewSecret = Secret, EventTypes = ["File.Upload"],
    });

    private async Task<WebhookDelivery> EnqueueAsync(int webhookId)
    {
        var delivery = WebhookSink.NewDelivery(webhookId, Guid.NewGuid(), "File.Upload", "{\"attempt\":0}", Now);
        await _host.Store.AddDeliveriesAsync([delivery], Ct);
        return delivery;
    }

    [Fact]
    public async Task A_claimed_delivery_is_not_given_to_another_node_until_its_lease_ends()
    {
        var id = await AddAsync();
        var delivery = await EnqueueAsync(id);

        var first = await _host.Store.ClaimDueAsync("node-a", Now, Now.AddMinutes(2), 10, Ct);
        var second = await _host.Store.ClaimDueAsync("node-b", Now.AddMinutes(1), Now.AddMinutes(3), 10, Ct);
        var afterLease = await _host.Store.ClaimDueAsync("node-b", Now.AddMinutes(3), Now.AddMinutes(5), 10, Ct);

        Assert.Equal(delivery.Id, Assert.Single(first).Id);
        Assert.Equal("node-a", first[0].LeaseOwner);
        Assert.Empty(second);
        Assert.Equal("node-b", Assert.Single(afterLease).LeaseOwner);
    }

    [Fact]
    public async Task A_delivery_that_is_not_due_yet_or_released_is_handled_correctly()
    {
        var id = await AddAsync();
        var delivery = await EnqueueAsync(id);

        Assert.Empty(await _host.Store.ClaimDueAsync("node-a", Now.AddSeconds(-1), Now.AddMinutes(2), 10, Ct));
        var claimed = Assert.Single(await _host.Store.ClaimDueAsync("node-a", Now, Now.AddMinutes(2), 10, Ct));
        await _host.Store.ReleaseAsync(claimed.Id, Ct);
        Assert.Single(await _host.Store.ClaimDueAsync("node-b", Now, Now.AddMinutes(2), 10, Ct));
        Assert.Equal(delivery.DeliveryId, claimed.DeliveryId);
    }

    [Fact]
    public async Task The_secret_is_encrypted_at_rest_and_not_in_the_provider_event()
    {
        var id = await AddAsync();

        var stored = await _host.Store.GetAsync(id, Ct);
        Assert.NotNull(stored!.ProtectedSecret);
        Assert.DoesNotContain(Secret, stored.ProtectedSecret);
        var protector = new WebhookSecretProtector(_host.Services.GetRequiredService<IDataProtectionProvider>());
        Assert.Equal(Secret, protector.TryUnprotect(stored.ProtectedSecret));

        await _host.Bus.PublishAsync(new SystemEvent(SystemEventType.Started), Ct); // the bus is in order: after this, the provider event is there
        await _events.SystemEventSeen.WaitAsync(TimeSpan.FromSeconds(60), Ct);
        var added = Assert.Single(_events.Events.OfType<ProviderEvent>());
        Assert.Equal((ProviderAction.Add, ProviderObjectType.Webhook, "hook"), (added.Action, added.ObjectType, added.ObjectName));
        Assert.True(((WebhookSnapshot)added.Object!).HasSecret);
        Assert.DoesNotContain(Secret, System.Text.Json.JsonSerializer.Serialize(added.Object));
    }

    [Fact]
    public async Task An_update_without_a_new_secret_keeps_it_and_RemoveSecret_removes_it()
    {
        var id = await AddAsync();
        var protectedSecret = (await _host.Store.GetAsync(id, Ct))!.ProtectedSecret;
        var input = WebhookInput.From((await _host.Store.GetAsync(id, Ct))!);

        Assert.True((await _host.Admin.SaveAsync(AdminActor.System, input with { TimeoutSeconds = 5 }, Ct)).Succeeded);
        Assert.Equal(protectedSecret, (await _host.Store.GetAsync(id, Ct))!.ProtectedSecret);

        Assert.True((await _host.Admin.SaveAsync(AdminActor.System, input with { RemoveSecret = true }, Ct)).Succeeded);
        Assert.Null((await _host.Store.GetAsync(id, Ct))!.ProtectedSecret);
    }

    [Fact]
    public async Task Names_are_unique_without_case_and_a_removed_webhook_takes_its_deliveries()
    {
        var id = await AddAsync("Hook");
        await EnqueueAsync(id);

        var duplicate = await _host.Admin.SaveAsync(AdminActor.System, new WebhookInput { Name = "HOOK", Url = "https://hooks.example.com/x" }, Ct);
        Assert.False(duplicate.Succeeded);

        Assert.True(await _host.Admin.RemoveAsync(AdminActor.System, id, Ct));
        Assert.Empty(await _host.Store.ListAsync(Ct));
        Assert.Empty(await _host.Store.ListDeliveriesAsync(id, 10, Ct));
    }

    [Fact]
    public async Task Old_finished_deliveries_are_removed_and_pending_ones_stay()
    {
        var id = await AddAsync();
        var old = await EnqueueAsync(id);
        var pending = await EnqueueAsync(id);
        old.Status = WebhookDeliveryStatus.Delivered;
        await _host.Store.SaveAttemptAsync(old, Ct);

        Assert.Equal(1, await _host.Store.DeleteFinishedOlderThanAsync(Now.AddDays(1), Ct));
        Assert.Equal(pending.Id, Assert.Single(await _host.Store.ListDeliveriesAsync(id, 10, Ct)).Id);
    }
}
