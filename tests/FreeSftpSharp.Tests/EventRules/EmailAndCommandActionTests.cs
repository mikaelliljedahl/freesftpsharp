using SshServer.EventRules;
using SshServer.EventRules.Actions;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;

namespace FreeSftpSharp.Tests.EventRules;

/// <summary>The Email action with a fake mail server, and the Command action with a fake process runner.</summary>
public sealed class EmailAndCommandActionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly string Tool = OperatingSystem.IsWindows() ? @"C:\tools\import.exe" : "/opt/tools/import";

    private static Dictionary<string, string?> CommandsAllowed(params string[] allowed)
    {
        var settings = new Dictionary<string, string?> { ["EventRules:AllowCommands"] = "true" };
        for (var i = 0; i < allowed.Length; i++)
            settings[$"EventRules:AllowedCommands:{i}"] = allowed[i];
        return settings;
    }

    private static async Task<EventRuleRun> RunAsync(EventRuleTestHost host, IEvent @event, params EventRuleAction[] actions)
    {
        var id = await host.AddRuleAsync(new EventRuleInput
        {
            Name = "r-" + Guid.NewGuid().ToString("N")[..6], Trigger = EventRuleTrigger.Event, EventTypes = [EventNames.Of(@event)], Actions = actions,
        });
        return await host.Runner.RunForEventAsync((await host.Store.GetAsync(id, Ct))!, @event, Ct);
    }

    [Fact]
    public async Task Email_renders_the_subject_and_text_and_attaches_the_file()
    {
        await using var host = new EventRuleTestHost();
        host.AddUser("alice");
        await MemoryFiles.WriteAsync(host.Files.For("alice"), "/in/report.csv", "a;b");

        var run = await RunAsync(host, EventRuleTestHost.Upload("alice", "/in/report.csv", size: 3), new EventRuleAction
        {
            Type = "Email",
            Options = new()
            {
                ["To"] = "ops@example.com, erp@example.com",
                ["Subject"] = "{{Name}}\r\nBcc: evil@example.com",
                ["Body"] = "{{Username}} sent {{FileSize}} bytes",
                ["AttachFile"] = "true",
            },
        });

        Assert.Equal(EventRuleRunStatus.Ok, run.Status);
        var mail = Assert.Single(host.Emails.Sent);
        Assert.Equal(["ops@example.com", "erp@example.com"], mail.To);
        Assert.Equal("report.csv Bcc: evil@example.com", mail.Subject); // no header injection through a line break
        Assert.Equal("alice sent 3 bytes", mail.Body);
        var attachment = Assert.Single(mail.Attachments);
        Assert.Equal("report.csv", attachment.FileName);
        Assert.Equal("a;b"u8.ToArray(), attachment.Content);
    }

    [Fact]
    public async Task Email_is_skipped_without_a_mail_server_and_the_run_is_not_a_failure()
    {
        await using var host = new EventRuleTestHost();
        host.Emails.IsConfigured = false;

        var run = await RunAsync(host, EventRuleTestHost.Upload("u", "/a"), new EventRuleAction { Type = "Email", Options = new() { ["To"] = "ops@example.com" } });

        Assert.Equal(EventRuleRunStatus.Ok, run.Status);
        Assert.Contains("Skipped", run.Message);
        Assert.Empty(host.Emails.Sent);
    }

    [Fact]
    public async Task The_real_sender_is_not_configured_without_a_host_and_an_address_must_be_valid()
    {
        await using var host = new EventRuleTestHost();
        var sender = new SmtpEmailSender(Microsoft.Extensions.Options.Options.Create(new EventRuleOptions()));
        Assert.False(sender.IsConfigured);
        Assert.False(host.Admin.IsEmailConfigured);

        var result = await host.Admin.SaveAsync(AdminActor.System, new EventRuleInput
        {
            Name = "bad-mail", Trigger = EventRuleTrigger.OnDemand,
            Actions = [new EventRuleAction { Type = "Email", Options = new() { ["To"] = "not an address" } }],
        }, Ct);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, e => e.Contains("not a valid email address"));
    }

    [Fact]
    public async Task A_command_is_refused_when_commands_are_disabled()
    {
        await using var host = new EventRuleTestHost();
        var action = new EventRuleAction { Type = "Command", Options = new() { ["Command"] = Tool } };

        var save = await host.Admin.SaveAsync(AdminActor.System, new EventRuleInput { Name = "cmd", Trigger = EventRuleTrigger.OnDemand, Actions = [action] }, Ct);
        Assert.False(save.Succeeded);
        Assert.Contains(save.Errors, e => e.Contains("Commands are disabled"));

        // A rule stored while commands were allowed does not run after they are turned off.
        var rule = new EventRule { Id = 0, Name = "stored", Trigger = EventRuleTrigger.OnDemand, Actions = [action] };
        Assert.True(await host.Store.AddAsync(rule, Ct));
        var runs = await host.Runner.RunWithoutEventAsync(new ActiveEventRule(rule), EventRuleRunner.OnDemandTrigger, Ct);
        Assert.Equal(EventRuleRunStatus.Failed, Assert.Single(runs).Status);
        Assert.Contains("Commands are disabled", runs[0].Message);
        Assert.Empty(host.Commands.Requests);
    }

    [Fact]
    public async Task A_command_that_is_not_on_the_allow_list_is_refused()
    {
        await using var host = new EventRuleTestHost(settings: CommandsAllowed(Tool));
        var other = OperatingSystem.IsWindows() ? @"C:\Windows\System32\cmd.exe" : "/bin/sh";
        var action = new EventRuleAction { Type = "Command", Options = new() { ["Command"] = other } };

        var save = await host.Admin.SaveAsync(AdminActor.System, new EventRuleInput { Name = "cmd", Trigger = EventRuleTrigger.OnDemand, Actions = [action] }, Ct);
        Assert.False(save.Succeeded);
        Assert.Contains(save.Errors, e => e.Contains("is not in EventRules:AllowedCommands"));

        var relative = await host.Admin.SaveAsync(AdminActor.System, new EventRuleInput
        {
            Name = "cmd2", Trigger = EventRuleTrigger.OnDemand,
            Actions = [new EventRuleAction { Type = "Command", Options = new() { ["Command"] = "import" } }],
        }, Ct);
        Assert.False(relative.Succeeded);

        var rule = new EventRule { Name = "stored", Trigger = EventRuleTrigger.OnDemand, Actions = [action] };
        Assert.True(await host.Store.AddAsync(rule, Ct));
        var runs = await host.Runner.RunWithoutEventAsync(new ActiveEventRule(rule), EventRuleRunner.OnDemandTrigger, Ct);
        Assert.Equal(EventRuleRunStatus.Failed, runs[0].Status);
        Assert.Empty(host.Commands.Requests);
    }

    [Fact]
    public async Task An_allowed_command_gets_each_argument_as_one_value_and_only_its_own_environment()
    {
        await using var host = new EventRuleTestHost(settings: CommandsAllowed(Tool));
        var hostile = "/in/x; rm -rf ~ $(id) `id`.csv";

        var run = await RunAsync(host, EventRuleTestHost.Upload("alice", hostile), new EventRuleAction
        {
            Type = "Command",
            Options = new()
            {
                ["Command"] = Tool,
                ["Arguments"] = "--file\n{{VirtualPath}}\n--user={{Username}}",
                ["Environment"] = "IMPORT_USER={{Username}}\nMODE=fast",
            },
        });

        Assert.Equal(EventRuleRunStatus.Ok, run.Status);
        var request = Assert.Single(host.Commands.Requests);
        Assert.Equal(Tool, request.Executable);
        Assert.Equal(["--file", hostile, "--user=alice"], request.Arguments);
        Assert.Equal(new Dictionary<string, string> { ["IMPORT_USER"] = "alice", ["MODE"] = "fast" }, request.Environment);
        Assert.Equal(TimeSpan.FromSeconds(EventRuleOptions.DefaultCommandTimeoutSeconds), request.Timeout);
    }

    [Fact]
    public async Task A_command_fails_on_an_exit_code_and_on_a_timeout()
    {
        await using var host = new EventRuleTestHost(settings: CommandsAllowed(Tool));
        var action = new EventRuleAction { Type = "Command", Options = new() { ["Command"] = Tool } };

        host.Commands.Result = _ => new CommandResult(3, false, "bad input");
        var exit = await RunAsync(host, EventRuleTestHost.Upload("u", "/a"), action);
        Assert.Equal(EventRuleRunStatus.Failed, exit.Status);
        Assert.Contains("exit code 3", exit.Message);
        Assert.Contains("bad input", exit.Message);

        host.Commands.Result = _ => new CommandResult(null, true, "");
        var timeout = await RunAsync(host, EventRuleTestHost.Upload("u", "/a"), action);
        Assert.Contains("was killed", timeout.Message);
    }

    [Fact]
    public async Task The_process_runner_passes_arguments_without_a_shell_and_clears_the_environment()
    {
        // A real process: /usr/bin/env without arguments prints its environment; with arguments it runs printf.
        var env = "/usr/bin/env";
        Assert.SkipUnless(File.Exists(env) && !OperatingSystem.IsWindows(), "Needs /usr/bin/env.");
        Environment.SetEnvironmentVariable("FREESFTPSHARP_SECRET_OF_THE_SERVER", "leak");
        var environment = new Dictionary<string, string> { ["PATH"] = "/usr/bin:/bin", ["ONLY"] = "this" };

        var printed = await new ProcessCommandRunner().RunAsync(new CommandRequest(env, [], environment, TimeSpan.FromSeconds(10)), Ct);
        var formatted = await new ProcessCommandRunner().RunAsync(new CommandRequest(env, ["printf", "[%s]", "a b", "$(id)"], environment,
            TimeSpan.FromSeconds(10)), Ct);

        Assert.Equal(0, printed.ExitCode);
        Assert.Contains("ONLY=this", printed.Output);
        Assert.DoesNotContain("FREESFTPSHARP_SECRET_OF_THE_SERVER", printed.Output);
        Assert.Equal(0, formatted.ExitCode);
        Assert.Equal("[a b][$(id)]", formatted.Output);
    }

    [Fact]
    public async Task The_process_runner_kills_a_command_at_the_timeout()
    {
        var sleep = File.Exists("/bin/sleep") ? "/bin/sleep" : "/usr/bin/sleep";
        Assert.SkipUnless(File.Exists(sleep) && !OperatingSystem.IsWindows(), "Needs sleep.");

        var result = await new ProcessCommandRunner().RunAsync(new CommandRequest(sleep, ["30"], new Dictionary<string, string>(),
            TimeSpan.FromMilliseconds(300)), Ct);

        Assert.True(result.TimedOut);
        Assert.Null(result.ExitCode);
    }
}
