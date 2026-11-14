using Microsoft.Extensions.DependencyInjection;
using SshServer.EventRules;
using SshServer.Interfaces.EventRules;

namespace FreeSftpSharp.Tests.EventRules;

/// <summary>An action plug-in of the tests: it records its runs and fails when its option "fail" is true.</summary>
public sealed class ScriptedAction : IEventRuleAction
{
    private readonly List<string> _log;

    public ScriptedAction(string type, List<string> log, bool needsUser = false)
    {
        Type = type;
        _log = log;
        NeedsUser = needsUser;
    }

    public string Type { get; }

    public string DisplayName => Type;

    public string Description => "A test action.";

    public bool NeedsUser { get; }

    public IReadOnlyList<EventActionField> Fields { get; } =
    [
        new("text", "Text", EventActionFieldKind.Text) { Placeholders = true },
        new("fail", "Fail", EventActionFieldKind.Boolean),
    ];

    public IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options) => [];

    public Task<EventActionResult> ExecuteAsync(EventActionContext context, CancellationToken ct)
    {
        var text = context.RenderOption("text");
        lock (_log)
            _log.Add($"{Type}:{text}:{context.User?.Username}");
        context.Values["Last"] = Type;
        return Task.FromResult(context.BoolOption("fail") ? EventActionResult.Failed("it failed") : EventActionResult.Ok("done " + text));
    }
}

public sealed class EventRuleRunnerTests : IAsyncDisposable
{
    private readonly List<string> _log = new();
    private readonly EventRuleTestHost _host;

    public EventRuleRunnerTests()
    {
        _host = new EventRuleTestHost(configure: services =>
        {
            services.AddSingleton<IEventRuleAction>(new ScriptedAction("A", _log));
            services.AddSingleton<IEventRuleAction>(new ScriptedAction("B", _log));
            services.AddSingleton<IEventRuleAction>(new ScriptedAction("OnFiles", _log, needsUser: true));
        });
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    private static EventRuleAction Step(string type, string text = "", bool fail = false, bool stop = false, bool failure = false) => new()
    {
        Type = type,
        Options = new Dictionary<string, string> { ["text"] = text, ["fail"] = fail.ToString() },
        StopOnFailure = stop,
        IsFailureAction = failure,
    };

    private async Task<EventRule> RuleAsync(EventRuleTrigger trigger, params EventRuleAction[] steps)
    {
        var id = await _host.AddRuleAsync(new EventRuleInput
        {
            Name = "rule-" + Guid.NewGuid().ToString("N")[..6],
            Trigger = trigger,
            EventTypes = trigger == EventRuleTrigger.Event ? ["File.Upload"] : [],
            CronExpression = trigger == EventRuleTrigger.Schedule ? "0 3 * * *" : null,
            Actions = steps,
        });
        return (await _host.Store.GetAsync(id, Ct))!;
    }

    [Fact]
    public async Task The_actions_run_in_order_with_the_placeholders_of_the_event_and_the_run_is_stored()
    {
        _host.AddUser("alice");
        var rule = await RuleAsync(EventRuleTrigger.Event, Step("A", "{{VirtualPath}}"), Step("B", "{{Last}}"));

        var run = await _host.Runner.RunForEventAsync(rule, EventRuleTestHost.Upload("alice", "/in/a.txt"), Ct);

        Assert.Equal(["A:/in/a.txt:alice", "B:A:alice"], _log);
        Assert.Equal(EventRuleRunStatus.Ok, run.Status);
        Assert.Equal("alice", run.Username);
        Assert.Equal("File.Upload", run.Trigger);
        var stored = Assert.Single(await _host.Store.ListRunsAsync(rule.Id, 10, Ct));
        Assert.Contains("1. A: Ok. done /in/a.txt", stored.Message);
        Assert.Contains("2. B: Ok. done A", stored.Message);
    }

    [Fact]
    public async Task A_failure_with_stop_on_failure_skips_the_next_actions_and_runs_the_failure_actions()
    {
        var rule = await RuleAsync(EventRuleTrigger.Event,
            Step("A", "first", fail: true, stop: true), Step("B", "second"), Step("A", "on failure", failure: true));

        var run = await _host.Runner.RunForEventAsync(rule, EventRuleTestHost.Upload("nobody", "/a"), Ct);

        Assert.Equal(["A:first:", "A:on failure:"], _log);
        Assert.Equal(EventRuleRunStatus.Failed, run.Status);
        Assert.Contains("stop on failure", run.Message);
        Assert.Contains("(failure action)", run.Message);
    }

    [Fact]
    public async Task A_failure_without_stop_runs_the_next_actions_and_the_failure_actions_do_not_run_after_success()
    {
        var failing = await RuleAsync(EventRuleTrigger.Event, Step("A", "1", fail: true), Step("B", "2"), Step("B", "f", failure: true));
        var passing = await RuleAsync(EventRuleTrigger.Event, Step("A", "3"), Step("B", "f2", failure: true));

        await _host.Runner.RunForEventAsync(failing, EventRuleTestHost.Upload("u", "/a"), Ct);
        await _host.Runner.RunForEventAsync(passing, EventRuleTestHost.Upload("u", "/a"), Ct);

        Assert.Equal(["A:1:", "B:2:", "B:f:", "A:3:"], _log);
    }

    [Fact]
    public async Task An_action_on_files_without_a_user_fails_and_a_missing_action_type_fails()
    {
        var rule = await RuleAsync(EventRuleTrigger.Event, Step("OnFiles"));
        rule.Actions.Add(Step("NotInstalled"));

        var run = await _host.Runner.RunForEventAsync(rule, EventRuleTestHost.Upload("ghost", "/a"), Ct);

        Assert.Equal(EventRuleRunStatus.Failed, run.Status);
        Assert.Contains("has no user", run.Message);
        Assert.Contains("NotInstalled is not installed", run.Message);
        Assert.Empty(_log);
    }

    [Fact]
    public async Task A_scheduled_rule_with_an_action_on_files_runs_once_per_matching_user()
    {
        _host.AddUser("partner-a");
        _host.AddUser("partner-b");
        _host.AddUser("staff");
        var id = await _host.AddRuleAsync(new EventRuleInput
        {
            Name = "per-user",
            Trigger = EventRuleTrigger.OnDemand,
            Conditions = new EventRuleConditions { Users = ["partner-*"] },
            Actions = [Step("OnFiles", "{{Username}}")],
        });

        var runs = await _host.Admin.RunNowAsync(SshServer.Interfaces.Admins.AdminActor.System, id, Ct);

        Assert.Equal(2, runs!.Count);
        Assert.Equal(["OnFiles:partner-a:partner-a", "OnFiles:partner-b:partner-b"], _log);
        Assert.All(runs, r => Assert.Equal(EventRuleRunner.OnDemandTrigger, r.Trigger));
    }

    [Fact]
    public async Task A_scheduled_rule_without_an_action_on_files_runs_once()
    {
        _host.AddUser("a");
        _host.AddUser("b");
        var rule = await RuleAsync(EventRuleTrigger.Schedule, Step("A", "{{Event}}"));

        var runs = await _host.Runner.RunWithoutEventAsync(new ActiveEventRule(rule), EventRuleRunner.ScheduleTrigger, Ct);

        Assert.Single(runs);
        Assert.Equal(["A:Schedule:"], _log);
    }

    [Fact]
    public async Task The_history_keeps_the_newest_runs()
    {
        await using var host = new EventRuleTestHost(settings: new Dictionary<string, string?> { ["EventRules:RunHistoryPerRule"] = "3" },
            configure: services => services.AddSingleton<IEventRuleAction>(new ScriptedAction("A", _log)));
        var id = await host.AddRuleAsync(new EventRuleInput { Name = "r", Trigger = EventRuleTrigger.Event, EventTypes = ["File.Upload"], Actions = [Step("A", "{{VirtualPath}}")] });
        var rule = (await host.Store.GetAsync(id, Ct))!;

        for (var i = 1; i <= 5; i++)
            await host.Runner.RunForEventAsync(rule, EventRuleTestHost.Upload("u", $"/{i}"), Ct);

        var runs = await host.Store.ListRunsAsync(id, 10, Ct);
        Assert.Equal(3, runs.Count);
        Assert.Contains("/5", runs[0].Message);
        Assert.Contains("/3", runs[2].Message);
    }
}
