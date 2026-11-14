using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Events;
using SshServer.Webhooks;

namespace FreeSftpSharp.Tests.Webhooks;

/// <summary>
/// The webhook administration service checks <see cref="AdminPermissions.ManageEvents"/> itself (#112), so an
/// administrator who lost the permission while the page is open (or code that calls the service directly) is refused.
/// </summary>
public sealed class WebhookAdministrationPermissionTests : IAsyncDisposable
{
    private static readonly AdminActor WithoutEvents = new("users-only", AdminPermissions.ManageUsers | AdminPermissions.ViewAudit, null);
    private static readonly AdminActor WithEvents = new("events", AdminPermissions.ManageEvents, null);

    private readonly WebhookTestHost _host = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    [Fact]
    public async Task An_admin_without_ManageEvents_is_refused_for_every_call()
    {
        var id = await _host.AddWebhookAsync(new WebhookInput { Name = "hook", Url = "https://hooks.example.com/x", EventTypes = ["File.Upload"] });
        var service = _host.Admin;

        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => service.ListAsync(WithoutEvents, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => service.GetAsync(WithoutEvents, id, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() =>
            service.SaveAsync(WithoutEvents, new WebhookInput { Name = "other", Url = "https://hooks.example.com/y" }, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() =>
            service.SaveAsync(WithoutEvents, new WebhookInput { Id = id, Name = "hook", Url = "https://hooks.example.com/changed" }, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => service.SendTestAsync(WithoutEvents, id, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => service.ListDeliveriesAsync(WithoutEvents, id, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => service.RedeliverAsync(WithoutEvents, 1, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => service.RemoveAsync(WithoutEvents, id, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => service.RemoveAsync(AdminActor.Anonymous, id, Ct));

        var stored = Assert.Single(await _host.Store.ListAsync(Ct));
        Assert.Equal("https://hooks.example.com/x", stored.Url);
        Assert.Empty(await _host.Store.ListDeliveriesAsync(id, 10, Ct));
    }

    [Fact]
    public async Task An_admin_with_ManageEvents_may_change_webhooks_and_is_the_actor_of_the_event()
    {
        var events = new List<IEvent>();
        await using var host = new WebhookTestHost(configure: services =>
            Microsoft.Extensions.DependencyInjection.ServiceCollectionServiceExtensions.AddSingleton<IEventSink>(services, new CollectingSink(events)));

        var result = await host.Admin.SaveAsync(WithEvents, new WebhookInput { Name = "hook", Url = "https://hooks.example.com/x" }, Ct);

        Assert.True(result.Succeeded, string.Join(" ", result.Errors));
        Assert.True(await host.Admin.RemoveAsync(WithEvents, result.Id!.Value, Ct));
        await WaitUntilAsync(() => ProviderEvents(events).Count == 2);
        Assert.All(ProviderEvents(events), e => Assert.Equal("events", e.Actor));
    }

    private static List<ProviderEvent> ProviderEvents(List<IEvent> events)
    {
        lock (events)
            return events.OfType<ProviderEvent>().ToList();
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "The condition was not met in time.");
            await Task.Delay(20, Ct);
        }
    }

    private sealed class CollectingSink(List<IEvent> events) : IEventSink
    {
        public ValueTask HandleAsync(IEvent @event, CancellationToken ct)
        {
            lock (events)
                events.Add(@event);
            return ValueTask.CompletedTask;
        }
    }
}
