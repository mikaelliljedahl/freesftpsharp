using SshServer.EventRules;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;

namespace FreeSftpSharp.Tests.EventRules;

/// <summary>The rules on the event bus: the sink runs them in the background, the hook decides the <c>Pre*</c> events.</summary>
public sealed class EventRuleSinkAndHookTests : IAsyncDisposable
{
    private readonly EventRuleTestHost _host = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    [Fact]
    public async Task With_no_rule_the_hook_allows_and_the_sink_does_nothing()
    {
        await _host.StartAsync();

        Assert.False((await _host.Hook.DecideAsync(new FileEvent(FileEventType.PreUpload) { Username = "u", VirtualPath = "/a" }, Ct)).IsDenied);
        await _host.Bus.PublishAsync(EventRuleTestHost.Upload("u", "/a"), Ct);
        Assert.Empty((await _host.Catalog.GetAsync(Ct)).EventRules);
    }

    [Fact]
    public async Task A_published_upload_runs_the_matching_rule_but_not_an_upload_of_an_action()
    {
        _host.AddUser("alice");
        await MemoryFiles.WriteAsync(_host.Files.For("alice"), "/in/a.txt", "a");
        await MemoryFiles.WriteAsync(_host.Files.For("alice"), "/in/b.txt", "b");
        var id = await _host.AddRuleAsync(new EventRuleInput
        {
            Name = "copy", Trigger = EventRuleTrigger.Event, EventTypes = ["File.Upload"], Conditions = new EventRuleConditions { PathGlob = "/in/*" },
            Actions = [new EventRuleAction { Type = "Copy", Options = new() { ["Target"] = "/out/{{Name}}" } }],
        });
        await _host.StartAsync();

        await _host.Bus.PublishAsync(EventRuleTestHost.Upload("alice", "/in/b.txt", protocol: EventRuleRunner.Protocol), Ct);
        await _host.Bus.PublishAsync(EventRuleTestHost.Upload("alice", "/other/x.txt"), Ct);
        await _host.Bus.PublishAsync(EventRuleTestHost.Upload("alice", "/in/a.txt"), Ct);

        var run = Assert.Single(await _host.WaitForRunsAsync(id, r => r.Count > 0));
        Assert.Equal(EventRuleRunStatus.Ok, run.Status);
        Assert.Equal("a", await MemoryFiles.ReadAsync(_host.Files.For("alice"), "/out/a.txt"));
        Assert.False(await MemoryFiles.ExistsAsync(_host.Files.For("alice"), "/out/b.txt"));
    }

    [Fact]
    public async Task A_rule_on_a_pre_event_refuses_the_operation_when_an_action_fails()
    {
        _host.AddUser("alice");
        await MemoryFiles.WriteAsync(_host.Files.For("alice"), "/approved/ok.csv", "x");
        await _host.AddRuleAsync(new EventRuleInput
        {
            Name = "only approved", Trigger = EventRuleTrigger.Event, EventTypes = ["File.PreDownload"],
            Actions = [new EventRuleAction { Type = "Exists", Options = new() { ["Paths"] = "/approved/{{Name}}" } }],
        });
        await _host.StartAsync();

        var allowed = await _host.Hook.DecideAsync(new FileEvent(FileEventType.PreDownload) { Username = "alice", VirtualPath = "/out/ok.csv" }, Ct);
        var denied = await _host.Hook.DecideAsync(new FileEvent(FileEventType.PreDownload) { Username = "alice", VirtualPath = "/out/secret.csv" }, Ct);
        var other = await _host.Hook.DecideAsync(new FileEvent(FileEventType.PreUpload) { Username = "alice", VirtualPath = "/out/secret.csv" }, Ct);

        Assert.False(allowed.IsDenied);
        Assert.True(denied.IsDenied);
        Assert.Contains("only approved", denied.Message);
        Assert.Equal("refused by the rule only approved", denied.ClientMessage);
        Assert.False(other.IsDenied);
    }

    [Fact]
    public async Task A_rule_on_a_pre_event_that_does_not_end_in_time_refuses_the_operation()
    {
        await using var host = new EventRuleTestHost(settings: new Dictionary<string, string?> { ["EventRules:SyncTimeoutSeconds"] = "1" });
        await host.AddRuleAsync(new EventRuleInput
        {
            Name = "slow", Trigger = EventRuleTrigger.Event, EventTypes = ["File.PreUpload"],
            Actions = [new EventRuleAction { Type = "Email", Options = new() { ["To"] = "ops@example.com" } }],
        });
        // The worker is not started: the run never ends.

        var decision = await host.Hook.DecideAsync(new FileEvent(FileEventType.PreUpload) { Username = "u", VirtualPath = "/a" }, Ct);

        Assert.True(decision.IsDenied);
        Assert.Contains("did not end within", decision.Message);
    }
}
