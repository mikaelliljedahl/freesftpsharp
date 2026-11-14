using SshServer.EventRules;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;

namespace FreeSftpSharp.Tests.EventRules;

public sealed class EventRuleAdministrationServiceTests : IAsyncDisposable
{
    private static readonly AdminActor WithoutEvents = new("users-only", AdminPermissions.ManageUsers, null);
    private static readonly AdminActor WithEvents = new("events-admin", AdminPermissions.ManageEvents, null);

    private readonly List<IEvent> _events = new();
    private readonly EventRuleTestHost _host;

    public EventRuleAdministrationServiceTests()
    {
        _host = new EventRuleTestHost(configure: services =>
            Microsoft.Extensions.DependencyInjection.ServiceCollectionServiceExtensions.AddSingleton<IEventSink>(services, new CollectingSink(_events)));
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    private static EventRuleInput Valid(string name = "rule") => new()
    {
        Name = name,
        Trigger = EventRuleTrigger.Event,
        EventTypes = ["file.upload"],
        Conditions = new EventRuleConditions { PathGlob = "/incoming/*", Statuses = ["ok"] },
        Actions = [new EventRuleAction { Type = "move", Options = new() { ["Target"] = "/processed/{{Name}}" } }],
    };

    [Fact]
    public async Task An_admin_without_ManageEvents_is_refused_for_every_call()
    {
        var id = await _host.AddRuleAsync(Valid() with { Trigger = EventRuleTrigger.OnDemand, EventTypes = [] });
        var service = _host.Admin;

        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => service.ListAsync(WithoutEvents, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => service.GetAsync(WithoutEvents, id, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => service.SaveAsync(WithoutEvents, Valid("other"), Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => service.RunNowAsync(WithoutEvents, id, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => service.ListRunsAsync(WithoutEvents, id, Ct));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() => service.RemoveAsync(AdminActor.Anonymous, id, Ct));

        Assert.Single(await _host.Store.ListAsync(Ct));
        Assert.Empty(await _host.Store.ListRunsAsync(id, 10, Ct));
    }

    [Fact]
    public async Task Save_stores_the_canonical_names_reloads_the_catalog_and_publishes_the_change_with_the_actor()
    {
        var result = await _host.Admin.SaveAsync(WithEvents, Valid(), Ct);

        Assert.True(result.Succeeded, string.Join(" ", result.Errors));
        var stored = (await _host.Store.GetAsync(result.Id!.Value, Ct))!;
        Assert.Equal(["File.Upload"], stored.EventTypes);
        Assert.Equal(["Ok"], stored.Conditions.Statuses);
        Assert.Equal("Move", stored.Actions[0].Type);
        Assert.Single((await _host.Catalog.GetAsync(Ct)).EventRules);

        Assert.True((await _host.Admin.SaveAsync(WithEvents, Valid() with { Id = result.Id, Enabled = false }, Ct)).Succeeded);
        Assert.Empty((await _host.Catalog.GetAsync(Ct)).EventRules);
        Assert.True(await _host.Admin.RemoveAsync(WithEvents, result.Id.Value, Ct));

        var changes = await WaitForProviderEventsAsync(3);
        Assert.Equal([ProviderAction.Add, ProviderAction.Update, ProviderAction.Delete], changes.Select(e => e.Action));
        Assert.All(changes, e => Assert.Equal(ProviderObjectType.EventRule, e.ObjectType));
        Assert.All(changes, e => Assert.Equal("events-admin", e.Actor));
        Assert.Equal(["Enabled"], changes[1].ChangedFields);
        // The options of the actions can have credentials: they are not in the event.
        Assert.IsType<EventRuleSnapshot>(changes[0].Object);
    }

    [Theory]
    [InlineData("mixed", "cannot have other events")]
    [InlineData("no-events", "Select one or more events")]
    [InlineData("bad-cron", "schedule is not valid")]
    [InlineData("bad-zone", "time zone")]
    [InlineData("no-actions", "Add one or more actions")]
    [InlineData("only-failure", "not a failure action")]
    [InlineData("unknown-type", "not installed")]
    [InlineData("glob", "starts with '/'")]
    [InlineData("sizes", "larger than the largest")]
    [InlineData("status", "Unknown file results")]
    [InlineData("target", "Enter the target")]
    [InlineData("filter", "is not known")]
    public async Task An_invalid_rule_is_refused_with_a_message(string problem, string message)
    {
        var input = problem switch
        {
            "mixed" => Valid() with { EventTypes = ["File.PreUpload", "File.Upload"] },
            "no-events" => Valid() with { EventTypes = [] },
            "bad-cron" => Valid() with { Trigger = EventRuleTrigger.Schedule, CronExpression = "every night" },
            "bad-zone" => Valid() with { Trigger = EventRuleTrigger.Schedule, CronExpression = "0 3 * * *", TimeZone = "Mars/Olympus" },
            "no-actions" => Valid() with { Actions = [] },
            "only-failure" => Valid() with { Actions = [new EventRuleAction { Type = "Move", Options = new() { ["Target"] = "/x" }, IsFailureAction = true }] },
            "unknown-type" => Valid() with { Actions = [new EventRuleAction { Type = "Teleport" }] },
            "glob" => Valid() with { Conditions = new EventRuleConditions { PathGlob = "incoming/*" } },
            "sizes" => Valid() with { Conditions = new EventRuleConditions { MinFileSize = 10, MaxFileSize = 5 } },
            "status" => Valid() with { Conditions = new EventRuleConditions { Statuses = ["Great"] } },
            "target" => Valid() with { Actions = [new EventRuleAction { Type = "Move" }] },
            "filter" => Valid() with { Actions = [new EventRuleAction { Type = "Move", Options = new() { ["Target"] = "/{{Name | rot13}}" } }] },
            _ => throw new ArgumentOutOfRangeException(nameof(problem)),
        };

        var result = await _host.Admin.SaveAsync(WithEvents, input, Ct);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, e => e.Contains(message));
        Assert.Empty(await _host.Store.ListAsync(Ct));
    }

    [Fact]
    public async Task Run_now_is_only_for_scheduled_and_on_demand_rules()
    {
        var onEvents = await _host.AddRuleAsync(Valid("on-events"));
        var manual = await _host.AddRuleAsync(new EventRuleInput
        {
            Name = "manual", Trigger = EventRuleTrigger.OnDemand,
            Actions = [new EventRuleAction { Type = "Email", Options = new() { ["To"] = "ops@example.com", ["Subject"] = "{{Event}} {{Rule}}" } }],
        });

        Assert.Null(await _host.Admin.RunNowAsync(WithEvents, onEvents, Ct));
        Assert.Null(await _host.Admin.RunNowAsync(WithEvents, 9999, Ct));
        var runs = await _host.Admin.RunNowAsync(WithEvents, manual, Ct);

        Assert.Equal(EventRuleRunStatus.Ok, Assert.Single(runs!).Status);
        Assert.Equal("OnDemand manual", Assert.Single(_host.Emails.Sent).Subject);
        Assert.Single(await _host.Admin.ListRunsAsync(WithEvents, manual, Ct));
    }

    [Fact]
    public async Task The_installed_action_types_are_listed_for_the_admin_UI()
    {
        var types = _host.Admin.ActionTypes.Select(a => a.Type).ToHashSet();

        Assert.Superset(new HashSet<string> { "Email", "Command", "Move", "Copy", "Delete", "CreateDirectory", "Exists", "Compress", "Retention" }, types);
        Assert.False(_host.Admin.AllowCommands);
    }

    private async Task<List<ProviderEvent>> WaitForProviderEventsAsync(int count)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (true)
        {
            List<ProviderEvent> found;
            lock (_events)
                found = _events.OfType<ProviderEvent>().ToList();
            if (found.Count >= count)
                return found;
            Assert.True(DateTime.UtcNow < deadline, $"Only {found.Count} provider events.");
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
