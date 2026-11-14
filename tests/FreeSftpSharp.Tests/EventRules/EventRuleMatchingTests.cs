using SshServer.EventRules;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;

namespace FreeSftpSharp.Tests.EventRules;

/// <summary>The trigger and the conditions of a rule (<see cref="ActiveEventRule.Matches"/>).</summary>
public sealed class EventRuleMatchingTests
{
    private static ActiveEventRule Rule(Action<EventRuleConditions>? conditions = null, params string[] events)
    {
        var rule = new EventRule { Name = "r", Trigger = EventRuleTrigger.Event, EventTypes = events.Length == 0 ? ["File.Upload"] : [.. events] };
        conditions?.Invoke(rule.Conditions);
        return new ActiveEventRule(rule);
    }

    private static bool Matches(ActiveEventRule rule, IEvent e) => rule.Matches(e, EventNames.Of(e));

    [Fact]
    public void Only_the_events_of_the_trigger_match()
    {
        var rule = Rule();

        Assert.True(Matches(rule, EventRuleTestHost.Upload("alice", "/a.txt")));
        Assert.False(Matches(rule, EventRuleTestHost.Upload("alice", "/a.txt") with { Type = FileEventType.Download }));
        Assert.False(Matches(rule, new AuthEvent(AuthEventType.LoginOk) { Username = "alice", Protocol = "SSH" }));
    }

    [Fact]
    public void A_user_pattern_matches_case_insensitively_with_wildcards()
    {
        var rule = Rule(c => c.Users = ["partner-*", "bob"]);

        Assert.True(Matches(rule, EventRuleTestHost.Upload("Partner-ACME", "/a")));
        Assert.True(Matches(rule, EventRuleTestHost.Upload("BOB", "/a")));
        Assert.False(Matches(rule, EventRuleTestHost.Upload("alice", "/a")));
        Assert.False(Matches(rule, EventRuleTestHost.Upload("bobby", "/a")));
    }

    [Fact]
    public void The_path_glob_matches_the_path_or_the_target_and_needs_a_file_event()
    {
        var rule = Rule(c => c.PathGlob = "/incoming/*", "File.Upload", "File.Rename", "Auth.LoginOk");

        Assert.True(Matches(rule, EventRuleTestHost.Upload("alice", "/incoming/a.csv")));
        Assert.False(Matches(rule, EventRuleTestHost.Upload("alice", "/incoming/sub/a.csv")));
        Assert.False(Matches(rule, EventRuleTestHost.Upload("alice", "/other/a.csv")));
        Assert.True(Matches(rule, new FileEvent(FileEventType.Rename) { Username = "alice", VirtualPath = "/tmp/a", VirtualTargetPath = "/incoming/a" }));
        Assert.False(Matches(rule, new AuthEvent(AuthEventType.LoginOk) { Username = "alice", Protocol = "SSH" }));
    }

    [Fact]
    public void Size_status_and_protocol_conditions()
    {
        var rule = Rule(c =>
        {
            c.MinFileSize = 10;
            c.MaxFileSize = 100;
            c.Statuses = ["Ok"];
            c.Protocols = ["sftp"];
        });

        Assert.True(Matches(rule, EventRuleTestHost.Upload("a", "/f", size: 50)));
        Assert.False(Matches(rule, EventRuleTestHost.Upload("a", "/f", size: 9)));
        Assert.False(Matches(rule, EventRuleTestHost.Upload("a", "/f", size: 101)));
        Assert.False(Matches(rule, EventRuleTestHost.Upload("a", "/f", size: 50) with { FileSize = null }));
        Assert.False(Matches(rule, EventRuleTestHost.Upload("a", "/f", size: 50) with { Status = FileEventStatus.Error }));
        Assert.False(Matches(rule, EventRuleTestHost.Upload("a", "/f", size: 50, protocol: "WebDAV")));
    }

    [Fact]
    public void Provider_events_match_by_object_type()
    {
        var rule = Rule(c => c.ObjectTypes = ["User"], "Provider.Add");

        Assert.True(Matches(rule, new ProviderEvent(ProviderAction.Add, ProviderObjectType.User, "bob")));
        Assert.False(Matches(rule, new ProviderEvent(ProviderAction.Add, ProviderObjectType.Webhook, "hook")));
    }

    [Fact]
    public void An_ip_ban_can_start_a_rule()
    {
        var rule = Rule(events: "Auth.IpBanned");

        Assert.True(Matches(rule, new AuthEvent(AuthEventType.IpBanned) { RemoteIp = "192.0.2.1", Protocol = "SSH" }));
    }

    [Fact]
    public void A_rule_on_pre_events_is_synchronous_and_the_catalog_sorts_the_rules_by_trigger()
    {
        var pre = new EventRule { Id = 1, Name = "pre", Trigger = EventRuleTrigger.Event, EventTypes = ["File.PreUpload"] };
        var after = new EventRule { Id = 2, Name = "after", Trigger = EventRuleTrigger.Event, EventTypes = ["File.Upload"] };
        var nightly = new EventRule { Id = 3, Name = "nightly", Trigger = EventRuleTrigger.Schedule, CronExpression = "0 3 * * *" };
        var manual = new EventRule { Id = 4, Name = "manual", Trigger = EventRuleTrigger.OnDemand };

        var snapshot = new EventRuleCatalogSnapshot([.. new[] { pre, after, nightly, manual }.Select(r => new ActiveEventRule(r))]);

        Assert.Equal("pre", Assert.Single(snapshot.PreEventRules).Name);
        Assert.Equal("after", Assert.Single(snapshot.EventRules).Name);
        Assert.Equal("nightly", Assert.Single(snapshot.ScheduledRules).Name);
        Assert.NotNull(snapshot.ScheduledRules[0].Cron);
    }

    [Fact]
    public void The_events_of_an_action_never_start_a_rule()
    {
        Assert.True(EventRuleRunner.IsFromAnAction(EventRuleTestHost.Upload("a", "/f", protocol: EventRuleRunner.Protocol)));
        Assert.False(EventRuleRunner.IsFromAnAction(EventRuleTestHost.Upload("a", "/f")));
    }

    [Fact]
    public void A_schedule_that_is_not_valid_any_more_has_an_error_and_no_cron()
    {
        var rule = new ActiveEventRule(new EventRule { Name = "bad", Trigger = EventRuleTrigger.Schedule, CronExpression = "not cron" });

        Assert.Null(rule.Cron);
        Assert.NotNull(rule.Error);
    }
}
