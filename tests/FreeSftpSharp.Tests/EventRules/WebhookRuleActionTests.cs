using FreeSftpSharp.Tests.Settings.Providers;
using System.Text.Json.Nodes;
using FreeSftpSharp.Tests.Settings;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.EventRules;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Webhooks;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.Webhooks;
using SshServer.Webhooks;

namespace FreeSftpSharp.Tests.EventRules;

/// <summary>The "Webhook" action (from AddWebhooks) puts the event of the rule in the outbox of a webhook.</summary>
public sealed class WebhookRuleActionTests : IAsyncDisposable
{
    private readonly TestDatabase _database = TestDatabase.CreateDefault();
    private readonly EventRuleTestHost _host;

    public WebhookRuleActionTests()
    {
        var options = _database.Options;
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();
        _host = new EventRuleTestHost(database: _database, configure: services =>
        {
            services.AddSingleton<IWebhookStore>(new SqlWebhookStore(options));
            services.AddWebhooks(configuration);
            services.Replace(ServiceDescriptor.Singleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider()));
        });
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private WebhookAdministrationService Webhooks => _host.Services.GetRequiredService<WebhookAdministrationService>();

    private IWebhookStore WebhookStore => _host.Services.GetRequiredService<IWebhookStore>();

    public async ValueTask DisposeAsync()
    {
        await _host.DisposeAsync();
        await _database.DisposeAsync();
    }

    [Fact]
    public async Task A_webhook_only_for_rules_gets_the_event_of_the_rule_and_none_of_its_own()
    {
        var saved = await Webhooks.SaveAsync(AdminActor.System, new WebhookInput
        {
            Name = "erp", Url = "https://erp.example.com/hook", OnlyForEventRules = true,
        }, Ct);
        Assert.True(saved.Succeeded, string.Join(" ", saved.Errors));
        var ruleId = await _host.AddRuleAsync(new EventRuleInput
        {
            Name = "tell the ERP", Trigger = EventRuleTrigger.Event, EventTypes = ["File.Upload"], Conditions = new EventRuleConditions { PathGlob = "/incoming/*" },
            Actions = [new EventRuleAction { Type = "Webhook", Options = new() { ["Webhook"] = "ERP" } }],
        });
        await _host.StartAsync();

        await _host.Bus.PublishAsync(EventRuleTestHost.Upload("alice", "/other/x.csv"), Ct);
        await _host.Bus.PublishAsync(EventRuleTestHost.Upload("alice", "/incoming/x.csv"), Ct);
        await _host.WaitForRunsAsync(ruleId, r => r.Count == 1);

        var delivery = Assert.Single(await WebhookStore.ListDeliveriesAsync(saved.Id!.Value, 10, Ct));
        Assert.Equal("File.Upload", delivery.EventType);
        var payload = JsonNode.Parse(delivery.Payload)!;
        Assert.Equal("tell the ERP", (string?)payload["rule"]);
        Assert.Equal("/incoming/x.csv", (string?)payload["virtual_path"]);
    }

    [Fact]
    public async Task A_scheduled_rule_sends_a_system_event_and_a_missing_webhook_fails_the_action()
    {
        var saved = await Webhooks.SaveAsync(AdminActor.System, new WebhookInput { Name = "ops", Url = "https://ops.example.com/hook", OnlyForEventRules = true }, Ct);
        var id = await _host.AddRuleAsync(new EventRuleInput
        {
            Name = "report", Trigger = EventRuleTrigger.OnDemand,
            Actions =
            [
                new EventRuleAction { Type = "Webhook", Options = new() { ["Webhook"] = "ops" } },
                new EventRuleAction { Type = "Webhook", Options = new() { ["Webhook"] = "nothing" } },
            ],
        });

        var run = Assert.Single((await _host.Admin.RunNowAsync(AdminActor.System, id, Ct))!);

        Assert.Equal(EventRuleRunStatus.Failed, run.Status);
        Assert.Contains("no enabled webhook nothing", run.Message);
        var delivery = Assert.Single(await WebhookStore.ListDeliveriesAsync(saved.Id!.Value, 10, Ct));
        Assert.Equal("System.ScheduledJobRan", delivery.EventType);
    }

    [Fact]
    public async Task A_webhook_only_for_rules_cannot_be_synchronous()
    {
        var result = await Webhooks.SaveAsync(AdminActor.System, new WebhookInput
        {
            Name = "bad", Url = "https://x.example.com", OnlyForEventRules = true, Sync = true, EventTypes = ["File.PreUpload"],
        }, Ct);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, e => e.Contains("cannot be synchronous"));
    }
}
