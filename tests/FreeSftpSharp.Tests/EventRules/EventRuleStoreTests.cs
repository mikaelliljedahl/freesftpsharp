using SshServer.Interfaces.EventRules;
using SshServer.Settings.Sql.EventRules;

namespace FreeSftpSharp.Tests.EventRules;

/// <summary>The SQLite store of the rules and their runs.</summary>
public sealed class EventRuleStoreTests : IAsyncDisposable
{
    private readonly EventRuleTestHost _host = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    private static EventRule NewRule(string name) => new()
    {
        Name = name,
        Trigger = EventRuleTrigger.Event,
        EventTypes = ["File.Upload"],
        Conditions = new EventRuleConditions { Users = ["a*"], PathGlob = "/in/*", MinFileSize = 1, Statuses = ["Ok"] },
        Actions = [new EventRuleAction { Type = "Move", Options = new() { ["Target"] = "/out/{{Name}}" }, StopOnFailure = true }],
    };

    [Fact]
    public async Task A_rule_is_stored_with_its_conditions_and_actions_and_the_name_is_unique()
    {
        var rule = NewRule("move");
        Assert.True(await _host.Store.AddAsync(rule, Ct));
        Assert.False(await _host.Store.AddAsync(NewRule("MOVE"), Ct));

        var stored = (await _host.Store.GetAsync(rule.Id, Ct))!;
        Assert.Equal(["a*"], stored.Conditions.Users);
        Assert.Equal("/in/*", stored.Conditions.PathGlob);
        Assert.Equal(1, stored.Conditions.MinFileSize);
        var action = Assert.Single(stored.Actions);
        Assert.Equal("/out/{{Name}}", action.Options["Target"]);
        Assert.True(action.StopOnFailure);

        stored.Actions[0].Options["Target"] = "/elsewhere";
        Assert.True(await _host.Store.UpdateAsync(stored, Ct));
        Assert.Equal("/elsewhere", (await _host.Store.GetAsync(rule.Id, Ct))!.Actions[0].Options["Target"]);
    }

    [Fact]
    public async Task An_occurrence_is_claimed_once_and_an_update_keeps_the_claim()
    {
        var rule = NewRule("claim");
        Assert.True(await _host.Store.AddAsync(rule, Ct));
        var tick = new DateTime(2026, 11, 2, 3, 0, 0, DateTimeKind.Utc);

        Assert.True(await _host.Store.TryClaimScheduledRunAsync(rule.Id, tick, Ct));
        Assert.False(await _host.Store.TryClaimScheduledRunAsync(rule.Id, tick, Ct));
        Assert.False(await _host.Store.TryClaimScheduledRunAsync(rule.Id, tick.AddDays(-1), Ct));

        var stored = (await _host.Store.GetAsync(rule.Id, Ct))!;
        stored.LastScheduledRunUtc = null;
        Assert.True(await _host.Store.UpdateAsync(stored, Ct));
        Assert.False(await _host.Store.TryClaimScheduledRunAsync(rule.Id, tick, Ct));
        Assert.True(await _host.Store.TryClaimScheduledRunAsync(rule.Id, tick.AddDays(1), Ct));
    }

    [Fact]
    public async Task Removing_a_rule_removes_its_runs()
    {
        var rule = NewRule("gone");
        Assert.True(await _host.Store.AddAsync(rule, Ct));
        await _host.Store.AddRunAsync(new EventRuleRun { RuleId = rule.Id, StartedUtc = DateTime.UtcNow, Trigger = "x", Message = new string('m', 5000) }, 10, Ct);
        Assert.Equal(EventRuleRun.MaxMessageLength, Assert.Single(await _host.Store.ListRunsAsync(rule.Id, 10, Ct)).Message.Length);

        Assert.True(await _host.Store.RemoveAsync(rule.Id, Ct));

        Assert.Null(await _host.Store.GetAsync(rule.Id, Ct));
        Assert.Empty(await _host.Store.ListRunsAsync(rule.Id, 10, Ct));
        Assert.False(await _host.Store.RemoveAsync(rule.Id, Ct));
    }

    [Fact]
    public async Task The_LiteDb_provider_has_no_rules()
    {
        var store = new DisabledEventRuleStore();

        Assert.False(store.IsEnabled);
        Assert.False(await store.AddAsync(NewRule("x"), Ct));
        Assert.Empty(await store.ListAsync(Ct));
    }
}
