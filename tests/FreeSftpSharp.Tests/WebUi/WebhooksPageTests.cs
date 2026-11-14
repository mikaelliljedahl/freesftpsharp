using FreeSftpSharp.Tests.Settings.Providers;
using Bunit;
using FreeSftpSharp.Tests.Webhooks;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces.Webhooks;
using SshServer.Webhooks;
using WebhooksPage = FxSshSftpServer.Components.Pages.Webhooks;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>The Webhooks page on the real application service and a SQLite store: add, the rules, test event, deliveries.</summary>
public sealed class WebhooksPageTests : AdminUiComponentContext, IAsyncLifetime
{
    // SQLite in every run: the page test expects the store calls to complete at once (the data in the first render).
    private readonly TestDatabase _database = TestDatabase.CreateSqlite();
    private readonly WebhookTestHost _host;

    public WebhooksPageTests()
    {
        _host = new WebhookTestHost(_database);
        Services.AddSingleton(_host.Admin);
    }

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    async ValueTask IAsyncDisposable.DisposeAsync()
    {
        await base.DisposeAsync();
        await _host.DisposeAsync();
        await _database.DisposeAsync();
    }

    [Fact]
    public void Without_webhooks_the_page_says_that_nothing_is_sent()
    {
        var page = Render<WebhooksPage>();

        Assert.NotNull(page.Find("#no-webhooks"));
    }

    [Fact]
    public async Task A_new_webhook_is_created_with_a_generated_secret_that_is_stored_encrypted()
    {
        var page = Render<WebhooksPage>();
        page.Find("#add-webhook").Click();
        var secret = page.Find("#webhook-secret").GetAttribute("value")!;
        Assert.Matches("^[0-9a-f]{64}$", secret);

        page.Find("#webhook-name").Change("uploads");
        page.Find("#webhook-url").Change("https://hooks.example.com/sftp");
        page.Find("#event-File-Upload").Change(true);
        page.Find("#webhook-form").Submit();

        page.WaitForAssertion(() => Assert.Contains("uploads", page.Find("#webhook-table").TextContent));
        var stored = Assert.Single(await _host.Store.ListAsync(CancellationToken.None));
        Assert.Equal(["File.Upload"], stored.EventTypes);
        Assert.NotNull(stored.ProtectedSecret);
        Assert.DoesNotContain(secret, stored.ProtectedSecret);
        Assert.DoesNotContain(secret, page.Markup);
    }

    [Fact]
    public async Task A_refused_rule_is_shown_and_nothing_is_saved()
    {
        var page = Render<WebhooksPage>();
        page.Find("#add-webhook").Click();
        page.Find("#webhook-name").Change("plain");
        page.Find("#webhook-url").Change("http://hooks.example.com/sftp");

        page.Find("#webhook-form").Submit();

        page.WaitForAssertion(() => Assert.Contains("https://", page.Find("#webhook-errors").TextContent));
        Assert.Empty(await _host.Store.ListAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Send_test_event_shows_the_queued_delivery()
    {
        await _host.AddWebhookAsync(new WebhookInput { Name = "receiver", Url = "https://hooks.example.com/x" });
        var page = Render<WebhooksPage>();

        page.Find(".send-test").Click();

        page.WaitForAssertion(() => Assert.Contains("System.WebhookTest", page.Find("#delivery-table").TextContent));
        Assert.Contains(nameof(WebhookDeliveryStatus.Pending), page.Find("#delivery-table").TextContent);
        Assert.NotNull(page.Find(".redeliver"));
    }
}
