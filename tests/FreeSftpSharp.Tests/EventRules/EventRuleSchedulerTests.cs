using FreeSftpSharp.Tests.Settings;
using Microsoft.Extensions.Time.Testing;
using SshServer.EventRules;
using SshServer.Interfaces.EventRules;

namespace FreeSftpSharp.Tests.EventRules;

/// <summary>The scheduled rules on a fake clock: the background loop, a retention rule, and two nodes on one database.</summary>
public sealed class EventRuleSchedulerTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static EventRuleAction Mail(string subject) => new()
    {
        Type = "Email",
        Options = new() { ["To"] = "ops@example.com", ["Subject"] = subject, ["Body"] = "{{RetentionReport}}" },
    };

    [Fact]
    public async Task A_nightly_retention_rule_runs_at_its_time_removes_only_old_files_and_reports_the_count()
    {
        var clock = new FakeTimeProvider(Start);
        await using var host = new EventRuleTestHost(time: clock);
        host.AddUser("alice");
        var files = host.Files.For("alice");
        await MemoryFiles.WriteAsync(files, "/tmp/old.log", "x", Start.UtcDateTime - TimeSpan.FromDays(10));
        await MemoryFiles.WriteAsync(files, "/tmp/new.log", "x", Start.UtcDateTime - TimeSpan.FromDays(1));
        var id = await host.AddRuleAsync(new EventRuleInput
        {
            Name = "nightly cleanup",
            Trigger = EventRuleTrigger.Schedule,
            CronExpression = "0 3 * * *",
            Actions =
            [
                new EventRuleAction { Type = "Retention", Options = new() { ["Folders"] = "/tmp", ["RetainDays"] = "7" } },
                Mail("{{RetentionDeleted}} files removed"),
            ],
        });
        await host.StartAsync(scheduler: true);

        // Before 03:00 nothing runs.
        clock.Advance(TimeSpan.FromHours(14));
        await Task.Delay(100, Ct);
        Assert.Empty(await host.Store.ListRunsAsync(id, 10, Ct));

        // At 03:00 the next day it runs once, also when the clock goes on.
        var runs = await host.WaitForRunsAsync(id, r => r.Count > 0, onPoll: () => clock.Advance(TimeSpan.FromMinutes(5)));
        var run = Assert.Single(runs);
        Assert.Equal(EventRuleRunStatus.Ok, run.Status);
        Assert.Equal(EventRuleRunner.ScheduleTrigger, run.Trigger);
        Assert.Equal("alice", run.Username);
        Assert.False(await MemoryFiles.ExistsAsync(files, "/tmp/old.log"));
        Assert.True(await MemoryFiles.ExistsAsync(files, "/tmp/new.log"));
        Assert.Equal("1 files removed", Assert.Single(host.Emails.Sent).Subject);
    }

    [Fact]
    public async Task Two_nodes_on_one_database_run_a_schedule_once_per_occurrence()
    {
        using var directory = new TempDirectory();
        var clock = new FakeTimeProvider(Start);
        await using var first = new EventRuleTestHost(time: clock, connectionString: directory.SqliteConnectionString());
        await using var second = new EventRuleTestHost(time: clock, connectionString: directory.SqliteConnectionString());
        var id = await first.AddRuleAsync(new EventRuleInput
        {
            Name = "hourly", Trigger = EventRuleTrigger.Schedule, CronExpression = "0 * * * *", Actions = [Mail("tick {{Date}}")],
        });
        var schedulers = new[] { first.Scheduler, second.Scheduler };

        for (var hour = 1; hour <= 3; hour++)
        {
            clock.Advance(TimeSpan.FromHours(1));
            var ran = await Task.WhenAll(schedulers.Select(s => s.RunDueAsync(Ct)));
            Assert.Equal(1, ran.Sum());
        }

        // Nothing is due again within the same hour.
        clock.Advance(TimeSpan.FromMinutes(10));
        Assert.Equal(0, (await Task.WhenAll(schedulers.Select(s => s.RunDueAsync(Ct)))).Sum());
        Assert.Equal(3, (await first.Store.ListRunsAsync(id, 10, Ct)).Count);
        Assert.Equal(3, first.Emails.Sent.Count + second.Emails.Sent.Count);
    }

    [Fact]
    public async Task Missed_occurrences_give_one_run_and_the_time_zone_of_the_rule_is_used()
    {
        var clock = new FakeTimeProvider(Start); // 12:00 UTC = 13:00 in Stockholm (winter time)
        await using var host = new EventRuleTestHost(time: clock);
        var id = await host.AddRuleAsync(new EventRuleInput
        {
            Name = "stockholm", Trigger = EventRuleTrigger.Schedule, CronExpression = "30 13 * * *", TimeZone = "Europe/Stockholm",
            Actions = [Mail("x")],
        });

        clock.Advance(TimeSpan.FromMinutes(29));
        Assert.Equal(0, await host.Scheduler.RunDueAsync(Ct));
        clock.Advance(TimeSpan.FromMinutes(2)); // 12:31 UTC = 13:31 local
        Assert.Equal(1, await host.Scheduler.RunDueAsync(Ct));
        clock.Advance(TimeSpan.FromDays(3)); // three occurrences missed: one run
        Assert.Equal(1, await host.Scheduler.RunDueAsync(Ct));
        Assert.Equal(2, (await host.Store.ListRunsAsync(id, 10, Ct)).Count);
    }

    [Fact]
    public async Task A_disabled_or_on_demand_rule_never_runs_on_a_schedule()
    {
        var clock = new FakeTimeProvider(Start);
        await using var host = new EventRuleTestHost(time: clock);
        await host.AddRuleAsync(new EventRuleInput
        {
            Name = "off", Enabled = false, Trigger = EventRuleTrigger.Schedule, CronExpression = "* * * * *", Actions = [Mail("x")],
        });
        await host.AddRuleAsync(new EventRuleInput { Name = "manual", Trigger = EventRuleTrigger.OnDemand, Actions = [Mail("x")] });

        clock.Advance(TimeSpan.FromHours(2));

        Assert.Equal(0, await host.Scheduler.RunDueAsync(Ct));
        Assert.Empty(host.Emails.Sent);
    }
}
