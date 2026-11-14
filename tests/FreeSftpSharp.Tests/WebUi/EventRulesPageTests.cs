using FreeSftpSharp.Tests.Settings.Providers;
using Bunit;
using FreeSftpSharp.Tests.EventRules;
using Microsoft.Extensions.DependencyInjection;
using SshServer.EventRules;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.EventRules;
using EventRulesPage = FxSshSftpServer.Components.Pages.EventRules;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>The Event rules page on the real application service and a SQLite store: add a rule, run it, the history.</summary>
public sealed class EventRulesPageTests : AdminUiComponentContext, IAsyncLifetime
{
    // SQLite in every run: the page test expects the store calls to complete at once (the data in the first render).
    private readonly TestDatabase _database = TestDatabase.CreateSqlite();
    private readonly EventRuleTestHost _host;

    public EventRulesPageTests()
    {
        _host = new EventRuleTestHost(database: _database);
        Services.AddSingleton(_host.Admin);
    }

    private static CancellationToken Ct => Xunit.TestContext.Current.CancellationToken;

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    async ValueTask IAsyncDisposable.DisposeAsync()
    {
        await base.DisposeAsync();
        await _host.DisposeAsync();
        await _database.DisposeAsync();
    }

    [Fact]
    public void Without_rules_the_page_says_that_nothing_runs_and_tells_what_is_off()
    {
        _host.Emails.IsConfigured = false;

        var page = Render<EventRulesPage>();

        Assert.NotNull(page.Find("#no-rules"));
        Assert.NotNull(page.Find("#commands-disabled"));
    }

    [Fact]
    public async Task A_new_rule_with_a_move_action_is_created()
    {
        var page = Render<EventRulesPage>();
        page.Click("#add-rule");
        page.Change("#rule-name", "process incoming");
        page.Change("#event-File-Upload", true);
        page.Change("#rule-path", "/incoming/*");
        page.Change("#add-action-type", "Move");
        page.Click("#add-action");
        page.Change("#action-0-Target", "/processed/{{Name}}");
        page.Change("#action-0-stop", true);

        page.Submit("#rule-form");

        page.WaitForAssertion(() => Assert.Contains("process incoming", page.Find("#rule-table").TextContent));
        var stored = Assert.Single(await _host.Store.ListAsync(Ct));
        Assert.Equal(EventRuleTrigger.Event, stored.Trigger);
        Assert.Equal(["File.Upload"], stored.EventTypes);
        Assert.Equal("/incoming/*", stored.Conditions.PathGlob);
        var action = Assert.Single(stored.Actions);
        Assert.Equal("Move", action.Type);
        Assert.Equal("/processed/{{Name}}", action.Options["Target"]);
        Assert.Equal("{{VirtualPath}}", action.Options["Source"]);
        Assert.True(action.StopOnFailure);
    }

    [Fact]
    public async Task A_refused_rule_shows_the_errors_and_nothing_is_saved()
    {
        var page = Render<EventRulesPage>();
        page.Click("#add-rule");
        page.Change("#rule-name", "no actions");
        page.Change("#event-File-Upload", true);

        page.Submit("#rule-form");

        page.WaitForAssertion(() => Assert.Contains("Add one or more actions", page.Find("#rule-errors").TextContent));
        Assert.Empty(await _host.Store.ListAsync(Ct));
    }

    [Fact]
    public async Task Run_now_shows_the_run_in_the_history()
    {
        await _host.AddRuleAsync(new EventRuleInput
        {
            Name = "report", Trigger = EventRuleTrigger.OnDemand,
            Actions = [new EventRuleAction { Type = "Email", Options = new() { ["To"] = "ops@example.com" } }],
        });
        var page = Render<EventRulesPage>();

        page.Click(".run-rule");

        page.WaitForAssertion(() => Assert.Contains("OnDemand", page.Find("#run-table").TextContent));
        Assert.Contains("Sent to ops@example.com", page.Find("#run-table").TextContent);
        Assert.Single(_host.Emails.Sent);
    }

    [Fact]
    public void An_admin_who_lost_ManageEvents_is_refused_by_the_service()
    {
        SignInAs(AdminPermissions.ManageUsers);

        Assert.Throws<AdminAccessDeniedException>(() => Render<EventRulesPage>());
        Assert.False(_host.Admin.ActionTypes.Count == 0);
    }
}
