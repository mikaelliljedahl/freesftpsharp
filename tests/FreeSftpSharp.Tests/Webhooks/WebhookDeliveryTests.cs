using FreeSftpSharp.Tests.Settings.Providers;
using SshServer.Interfaces.Admins;
using System.Diagnostics;
using FreeSftpSharp.Tests.Settings;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Webhooks;
using SshServer.Webhooks;

namespace FreeSftpSharp.Tests.Webhooks;

/// <summary>
/// The asynchronous webhooks end to end in the process: event, sink, outbox, dispatcher, an HTTP receiver on Kestrel. The
/// clock of the retries is a <see cref="FakeTimeProvider"/>; the test moves it forward while it waits.
/// </summary>
public sealed class WebhookDeliveryTests : IAsyncDisposable
{
    private const string Secret = "receiver-secret-0123456789abcdef";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero));
    private WebhookReceiver _receiver = null!;
    private readonly List<WebhookTestHost> _hosts = [];

    public async ValueTask DisposeAsync()
    {
        foreach (var host in _hosts)
            await host.DisposeAsync();
        if (_receiver != null)
            await _receiver.DisposeAsync();
    }

    private async Task<WebhookTestHost> StartHostAsync(TestDatabase? database = null, IDataProtectionProvider? keys = null, bool start = true)
    {
        _receiver ??= await WebhookReceiver.StartAsync(() => _time.GetUtcNow());
        var host = new WebhookTestHost(database, _time, keys);
        _hosts.Add(host);
        if (start)
            await host.StartAsync();
        return host;
    }

    private WebhookInput Hook(string name = "uploads", params string[] events) => new()
    {
        Name = name,
        Url = _receiver.Url("/" + name),
        NewSecret = Secret,
        EventTypes = events.Length == 0 ? ["File.Upload"] : events,
        Headers = new Dictionary<string, string> { ["X-Api-Key"] = "static-header-value" },
    };

    private FileEvent Upload(string path = "/in/a.csv") => new(FileEventType.Upload)
    {
        Timestamp = _time.GetUtcNow(), Username = "alice", VirtualPath = path, FileSize = 3, Status = FileEventStatus.Ok, Protocol = "SFTP", RemoteIp = "192.0.2.1",
    };

    /// <summary>Moves the fake clock forward by <paramref name="step"/> on each poll of a wait.</summary>
    private Action Advance(TimeSpan step) => () => _time.Advance(step);

    [Fact]
    public async Task An_upload_gives_exactly_one_POST_with_a_valid_signature_and_the_headers()
    {
        var host = await StartHostAsync();
        var id = await host.AddWebhookAsync(Hook());

        await host.Sink.HandleAsync(Upload(), Ct);
        await host.Sink.HandleAsync(new FileEvent(FileEventType.Download) { Timestamp = _time.GetUtcNow(), Username = "alice", VirtualPath = "/x" }, Ct);

        var delivery = Assert.Single(await host.WaitForDeliveriesAsync(id, d => d.Count == 1 && d[0].Status == WebhookDeliveryStatus.Delivered));
        var request = Assert.Single(_receiver.Requests);
        Assert.Equal("POST", request.Method);
        Assert.Equal("/uploads", request.Path);
        Assert.StartsWith("application/json", request.Header("Content-Type"));
        Assert.Equal("static-header-value", request.Header("X-Api-Key"));
        Assert.Equal("File.Upload", request.Header(WebhookSignature.EventHeader));
        Assert.Equal(delivery.DeliveryId.ToString(), request.Header(WebhookSignature.DeliveryHeader));
        Assert.True(WebhookSignature.Verify(Secret, request.Header(WebhookSignature.SignatureHeader), request.Body, _time.GetUtcNow(), TimeSpan.FromMinutes(5)),
            $"Bad signature {request.Header(WebhookSignature.SignatureHeader)}");
        Assert.Equal(1, request.Json.GetProperty("attempt").GetInt32());
        Assert.Equal(delivery.EventId.ToString(), request.Json.GetProperty("event_id").GetString());
        Assert.Equal("/in/a.csv", request.Json.GetProperty("virtual_path").GetString());
        Assert.DoesNotContain(Secret, request.Body);
    }

    [Fact]
    public async Task A_receiver_that_answers_500_twice_and_then_200_gets_three_attempts_with_growing_delays_and_the_delivery_is_Delivered()
    {
        var host = await StartHostAsync();
        _receiver.Respond = (_, index) => new ReceiverAnswer(index < 2 ? 500 : 200, index < 2 ? "{\"error\":\"busy\"}" : "ok");
        var id = await host.AddWebhookAsync(Hook());

        await host.Sink.HandleAsync(Upload(), Ct);
        var deliveries = await host.WaitForDeliveriesAsync(id, d => d.Count == 1 && d[0].Status == WebhookDeliveryStatus.Delivered,
            TimeSpan.FromSeconds(60), Advance(TimeSpan.FromSeconds(2)));

        var delivery = Assert.Single(deliveries);
        Assert.Equal(3, delivery.Attempts);
        Assert.Equal(200, delivery.LastStatusCode);
        Assert.Null(delivery.LastError);
        var requests = _receiver.Requests;
        Assert.Equal(3, requests.Count);
        Assert.Equal([1, 2, 3], requests.Select(r => r.Json.GetProperty("attempt").GetInt32()));
        Assert.All(requests, r => Assert.Equal(delivery.DeliveryId.ToString(), r.Header(WebhookSignature.DeliveryHeader)));
        var first = requests[1].ReceivedAt - requests[0].ReceivedAt;
        var second = requests[2].ReceivedAt - requests[1].ReceivedAt;
        Assert.True(first >= TimeSpan.FromSeconds(10), $"The first retry came after {first}.");
        Assert.True(second >= TimeSpan.FromMinutes(1), $"The second retry came after {second}.");
        Assert.True(second > first, $"The delays did not grow: {first}, {second}.");
    }

    [Fact]
    public async Task A_receiver_that_always_fails_makes_a_dead_letter_after_six_attempts_and_Redeliver_sends_it_again()
    {
        var host = await StartHostAsync();
        _receiver.Respond = (_, _) => new ReceiverAnswer(503);
        var id = await host.AddWebhookAsync(Hook());

        await host.Sink.HandleAsync(Upload(), Ct);
        var dead = Assert.Single(await host.WaitForDeliveriesAsync(id, d => d.Count == 1 && d[0].Status == WebhookDeliveryStatus.DeadLetter,
            TimeSpan.FromSeconds(90), Advance(TimeSpan.FromMinutes(1))));
        Assert.Equal(WebhookRetrySchedule.MaxAttempts, dead.Attempts);
        Assert.Equal(WebhookRetrySchedule.MaxAttempts, _receiver.Requests.Count);
        Assert.Equal("HTTP 503", dead.LastError);

        _receiver.Respond = (_, _) => new ReceiverAnswer(204);
        Assert.True(await host.Admin.RedeliverAsync(AdminActor.System, dead.Id, Ct));
        var delivered = Assert.Single(await host.WaitForDeliveriesAsync(id, d => d[0].Status == WebhookDeliveryStatus.Delivered));
        Assert.Equal(1, delivered.Attempts);
        Assert.Equal(WebhookRetrySchedule.MaxAttempts + 1, _receiver.Requests.Count);
    }

    [Fact]
    public async Task A_delivery_whose_request_outlasts_its_lease_is_not_sent_again_while_it_is_in_flight()
    {
        // Each answer takes 300 ms while the clock runs 1 min per 20 ms: every attempt outlasts the 2 min lease on the
        // clock of the dispatcher. The dispatcher must not take the row again while its own attempt is in flight.
        var host = await StartHostAsync();
        _receiver.Respond = (_, _) => new ReceiverAnswer(503, Delay: TimeSpan.FromMilliseconds(300));
        var id = await host.AddWebhookAsync(Hook());

        await host.Sink.HandleAsync(Upload(), Ct);
        var dead = Assert.Single(await host.WaitForDeliveriesAsync(id, d => d.Count == 1 && d[0].Status == WebhookDeliveryStatus.DeadLetter,
            TimeSpan.FromSeconds(90), Advance(TimeSpan.FromMinutes(1))));

        Assert.Equal(WebhookRetrySchedule.MaxAttempts, dead.Attempts);
        Assert.Equal(Enumerable.Range(1, WebhookRetrySchedule.MaxAttempts), _receiver.Requests.Select(r => r.Json.GetProperty("attempt").GetInt32()));
    }

    [Fact]
    public async Task Pending_deliveries_survive_a_stop_and_are_delivered_after_the_next_start()
    {
        await using var database = TestDatabase.CreateDefault();
        var keys = new EphemeralDataProtectionProvider(); // the same data protection keys for both starts
        var first = await StartHostAsync(database, keys);
        _receiver.Respond = (_, _) => new ReceiverAnswer(500);
        var id = await first.AddWebhookAsync(Hook());

        await first.Sink.HandleAsync(Upload("/in/1.csv"), Ct);
        await first.Sink.HandleAsync(Upload("/in/2.csv"), Ct);
        await first.WaitForDeliveriesAsync(id, d => d.Count == 2 && d.All(x => x.Attempts == 1));
        await first.StopAsync();

        _receiver.Respond = (_, _) => new ReceiverAnswer(200);
        var second = await StartHostAsync(database, keys);
        var deliveries = await second.WaitForDeliveriesAsync(id, d => d.Count == 2 && d.All(x => x.Status == WebhookDeliveryStatus.Delivered),
            TimeSpan.FromSeconds(30), Advance(TimeSpan.FromSeconds(2)));

        Assert.All(deliveries, d => Assert.Equal(2, d.Attempts));
        var signed = _receiver.Requests.Where(r => r.Json.GetProperty("attempt").GetInt32() == 2).ToList();
        Assert.Equal(2, signed.Count);
        Assert.All(signed, r => Assert.True(WebhookSignature.Verify(Secret, r.Header(WebhookSignature.SignatureHeader), r.Body, _time.GetUtcNow(), TimeSpan.FromHours(1))));
    }

    [Fact]
    public async Task A_redirect_is_not_followed()
    {
        var host = await StartHostAsync();
        _receiver.Respond = (r, _) => r.Path == "/uploads" ? new ReceiverAnswer(307, Location: _receiver.Url("/elsewhere")) : new ReceiverAnswer(200);
        var id = await host.AddWebhookAsync(Hook());

        await host.Sink.HandleAsync(Upload(), Ct);

        var delivery = Assert.Single(await host.WaitForDeliveriesAsync(id, d => d.Count == 1 && d[0].Attempts == 1));
        Assert.Equal(WebhookDeliveryStatus.Pending, delivery.Status);
        Assert.Equal(307, delivery.LastStatusCode);
        Assert.Equal(["/uploads"], _receiver.Requests.Select(r => r.Path));
    }

    [Fact]
    public async Task A_dead_endpoint_does_not_slow_the_sink_and_the_response_excerpt_is_at_most_4_KiB()
    {
        var host = await StartHostAsync();
        _receiver.Respond = (_, _) => new ReceiverAnswer(500, new string('x', 100_000), Delay: TimeSpan.FromSeconds(3));
        var id = await host.AddWebhookAsync(Hook());

        var watch = Stopwatch.StartNew();
        for (var i = 0; i < 20; i++)
            await host.Sink.HandleAsync(Upload($"/in/{i}.csv"), Ct);
        watch.Stop();

        // The sink only writes the outbox; the slow answers come later.
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(3), $"The sink took {watch.Elapsed}.");
        var failed = await host.WaitForDeliveriesAsync(id, d => d.Count(x => x.Attempts == 1) >= 1);
        Assert.All(failed.Where(d => d.ResponseExcerpt != null), d => Assert.Equal(WebhookSender.MaxResponseBytes, d.ResponseExcerpt!.Length));
    }

    [Fact]
    public async Task The_filters_select_the_events_by_type_user_and_path()
    {
        var host = await StartHostAsync();
        var all = await host.AddWebhookAsync(Hook("all") with { EventTypes = [] });
        var filtered = await host.AddWebhookAsync(Hook("csv-of-alice") with { Users = ["ALICE"], PathGlob = "/in/**/*.csv" });

        await host.Sink.HandleAsync(Upload("/in/sub/a.csv"), Ct);
        await host.Sink.HandleAsync(Upload("/in/a.txt"), Ct);
        await host.Sink.HandleAsync(Upload("/in/b.csv") with { Username = "bob" }, Ct);
        await host.Sink.HandleAsync(Upload() with { Type = FileEventType.PreUpload }, Ct); // a Pre* event must be named
        await host.Sink.HandleAsync(new AuthEvent(AuthEventType.LoginOk) { Timestamp = _time.GetUtcNow(), Username = "alice" }, Ct);

        // "all" also gets the Provider.Add events of the two webhooks themselves.
        var everything = await host.WaitForDeliveriesAsync(all, d => d.Count == 6 && d.All(x => x.Status == WebhookDeliveryStatus.Delivered));
        Assert.Equal(["Auth.LoginOk", "File.Upload", "File.Upload", "File.Upload", "Provider.Add", "Provider.Add"], everything.Select(d => d.EventType).Order());
        var selected = Assert.Single(await host.WaitForDeliveriesAsync(filtered, d => d.Count >= 1 && d[0].Status == WebhookDeliveryStatus.Delivered));
        Assert.Contains("/in/sub/a.csv", selected.Payload);
        Assert.Single(_receiver.Requests, r => r.Path == "/csv-of-alice");
    }

    [Fact]
    public async Task Send_test_event_delivers_a_test_event_to_that_webhook_only()
    {
        var host = await StartHostAsync();
        var id = await host.AddWebhookAsync(Hook("first"));
        await host.AddWebhookAsync(Hook("second"));

        Assert.True(await host.Admin.SendTestAsync(AdminActor.System, id, Ct));

        await host.WaitForDeliveriesAsync(id, d => d.Count == 1 && d[0].Status == WebhookDeliveryStatus.Delivered);
        var request = Assert.Single(_receiver.Requests);
        Assert.Equal("/first", request.Path);
        Assert.Equal("System.WebhookTest", request.Header(WebhookSignature.EventHeader));
    }

    [Fact]
    public async Task With_no_webhook_an_event_writes_nothing()
    {
        var host = await StartHostAsync();

        await host.Sink.HandleAsync(Upload(), Ct);

        Assert.Empty(await host.Admin.ListAsync(AdminActor.System, Ct));
        Assert.Empty(await host.Store.ClaimDueAsync("test", DateTime.MaxValue.AddDays(-1), DateTime.MaxValue, 10, Ct));
        Assert.Empty(_receiver.Requests);
    }
}
