using FreeSftpSharp.Tests.Settings.Providers;
using SshServer.Interfaces.Admins;
using System.Diagnostics;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Webhooks;
using SshServer.Webhooks;

namespace FreeSftpSharp.Tests.Webhooks;

/// <summary>The synchronous Pre* webhooks: 2xx allows, 403 denies with the message, an error or a timeout denies unless fail open.</summary>
public sealed class WebhookEventHookTests : IAsyncLifetime
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private WebhookReceiver _receiver = null!;
    private WebhookTestHost _host = null!;

    public async ValueTask InitializeAsync()
    {
        _receiver = await WebhookReceiver.StartAsync();
        _host = new WebhookTestHost();
    }

    public async ValueTask DisposeAsync()
    {
        await _host.DisposeAsync();
        await _receiver.DisposeAsync();
    }

    private WebhookInput SyncHook(string name, bool failOpen = false, int timeout = 10) => new()
    {
        Name = name, Url = _receiver.Url("/" + name), Sync = true, FailOpen = failOpen, TimeoutSeconds = timeout,
        EventTypes = ["File.PreUpload"], NewSecret = "sync-secret-0123456789",
    };

    private static FileEvent PreUpload(string path = "/in/a.csv") => new(FileEventType.PreUpload)
    {
        Timestamp = DateTimeOffset.UtcNow, Username = "alice", VirtualPath = path, Protocol = "SFTP", RemoteIp = "127.0.0.1",
    };

    [Fact]
    public async Task Without_a_sync_webhook_the_hook_allows_at_once_without_a_request()
    {
        await _host.AddWebhookAsync(new WebhookInput { Name = "async", Url = _receiver.Url(), EventTypes = ["File.PreUpload"] });

        var decision = _host.Hook.DecideAsync(PreUpload(), Ct);

        Assert.True(decision.IsCompletedSuccessfully);
        Assert.False((await decision).IsDenied);
        Assert.False((await _host.Hook.DecideAsync(new FileEvent(FileEventType.Upload), Ct)).IsDenied);
        Assert.Empty(_receiver.Requests);
    }

    [Fact]
    public async Task A_2xx_allows_and_the_answer_is_in_the_deliveries()
    {
        var id = await _host.AddWebhookAsync(SyncHook("check"));
        _receiver.Respond = (_, _) => new ReceiverAnswer(204);

        var decision = await _host.Hook.DecideAsync(PreUpload(), Ct);

        Assert.False(decision.IsDenied);
        var request = Assert.Single(_receiver.Requests);
        Assert.Equal("File.PreUpload", request.Header(WebhookSignature.EventHeader));
        Assert.Equal("pre-upload", request.Json.GetProperty("action").GetString());
        Assert.NotNull(request.Header(WebhookSignature.SignatureHeader));
        var delivery = Assert.Single(await _host.Store.ListDeliveriesAsync(id, 10, Ct));
        Assert.Equal((true, WebhookDeliveryStatus.Delivered, 204), (delivery.Sync, delivery.Status, delivery.LastStatusCode));
    }

    [Fact]
    public async Task A_403_denies_with_the_message_of_the_body()
    {
        await _host.AddWebhookAsync(SyncHook("scanner"));
        _receiver.Respond = (_, _) => new ReceiverAnswer(403, "{\"message\":\"virus found\"}");

        var decision = await _host.Hook.DecideAsync(PreUpload(), Ct);

        Assert.True(decision.IsDenied);
        Assert.Equal("virus found", decision.ClientMessage);
        Assert.Contains("scanner", decision.Message);
    }

    [Fact]
    public async Task No_answer_within_the_timeout_denies()
    {
        var id = await _host.AddWebhookAsync(SyncHook("slow", timeout: 1));
        _receiver.Respond = (_, _) => new ReceiverAnswer(200, Delay: TimeSpan.FromSeconds(10));

        var watch = Stopwatch.StartNew();
        var decision = await _host.Hook.DecideAsync(PreUpload(), Ct);
        watch.Stop();

        Assert.True(decision.IsDenied);
        Assert.Null(decision.ClientMessage);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"The hook waited {watch.Elapsed}.");
        var delivery = Assert.Single(await _host.Store.ListDeliveriesAsync(id, 10, Ct));
        Assert.Equal(WebhookDeliveryStatus.Failed, delivery.Status);
        Assert.Contains("1 s", delivery.LastError);
    }

    [Fact]
    public async Task A_500_denies_but_a_fail_open_webhook_allows()
    {
        _receiver.Respond = (_, _) => new ReceiverAnswer(500);
        var closed = await _host.AddWebhookAsync(SyncHook("closed"));

        Assert.True((await _host.Hook.DecideAsync(PreUpload(), Ct)).IsDenied);

        var saved = await _host.Admin.SaveAsync(AdminActor.System, SyncHook("closed", failOpen: true) with { Id = closed }, Ct);
        Assert.True(saved.Succeeded, string.Join(" ", saved.Errors));
        Assert.False((await _host.Hook.DecideAsync(PreUpload(), Ct)).IsDenied);
    }

    [Fact]
    public async Task The_path_filter_selects_the_files_that_are_asked_for()
    {
        await _host.AddWebhookAsync(SyncHook("csv") with { PathGlob = "/**/*.csv" });
        _receiver.Respond = (_, _) => new ReceiverAnswer(403);

        Assert.False((await _host.Hook.DecideAsync(PreUpload("/in/a.txt"), Ct)).IsDenied);
        Assert.True((await _host.Hook.DecideAsync(PreUpload("/in/a.csv"), Ct)).IsDenied);
        Assert.Single(_receiver.Requests);
    }

    [Fact]
    public async Task An_http_webhook_is_not_called_when_AllowInsecureWebhooks_is_turned_off_later()
    {
        var id = await _host.AddWebhookAsync(SyncHook("insecure"));
        await using var strict = new WebhookTestHost(_host.Database, allowInsecure: false, dataProtection: _host.DataProtection);

        var decision = await strict.Hook.DecideAsync(PreUpload(), Ct);

        Assert.True(decision.IsDenied); // fail closed: the webhook cannot run
        Assert.Empty(_receiver.Requests);
        Assert.Contains(await strict.Store.ListDeliveriesAsync(id, 10, Ct), d => d.LastError!.Contains("AllowInsecureWebhooks", StringComparison.Ordinal));
    }
}
