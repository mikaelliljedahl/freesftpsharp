using System.Diagnostics;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Webhooks;
using Renci.SshNet.Common;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Webhooks;
using SshServer.Webhooks;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// The server with the webhooks plug-in (AddSshServerEvents + AddWebhooks on a SQLite database) and a receiver on
/// Kestrel: a synchronous scanner that answers 403 for files named denied*, a synchronous webhook that never answers in
/// time for files named slow*, and an asynchronous webhook for every upload.
/// </summary>
public sealed class WebhookServerFixture : SftpServerFixture
{
    public const string Secret = "end-to-end-webhook-secret-0123456789";
    public const string ScannerMessage = "uploads named denied* are refused by the scanner";

    public WebhookReceiver Receiver { get; private set; } = null!;
    public WebhookTestHost Webhooks { get; private set; } = null!;
    public int UploadWebhookId { get; private set; }

    public override async ValueTask InitializeAsync()
    {
        Receiver = await WebhookReceiver.StartAsync();
        Receiver.Respond = (request, _) => request.Path switch
        {
            "/scanner" => new ReceiverAnswer(403, $"{{\"message\":\"{ScannerMessage}\"}}"),
            "/slow" => new ReceiverAnswer(200, Delay: TimeSpan.FromSeconds(20)),
            _ => new ReceiverAnswer(200),
        };
        Webhooks = new WebhookTestHost();
        await Webhooks.AddWebhookAsync(new WebhookInput
        {
            Name = "scanner", Url = Receiver.Url("/scanner"), Sync = true, EventTypes = ["File.PreUpload"], PathGlob = "/**/denied*",
        });
        await Webhooks.AddWebhookAsync(new WebhookInput
        {
            Name = "slow", Url = Receiver.Url("/slow"), Sync = true, EventTypes = ["File.PreUpload"], PathGlob = "/**/slow*", TimeoutSeconds = 1,
        });
        UploadWebhookId = await Webhooks.AddWebhookAsync(new WebhookInput
        {
            Name = "uploads", Url = Receiver.Url("/uploads"), EventTypes = ["File.Upload"], NewSecret = Secret,
        });
        await Webhooks.StartAsync();
        await base.InitializeAsync();
    }

    protected override IEventBus CreateEventBus() => Webhooks.Bus;

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        await Webhooks.DisposeAsync();
        await Receiver.DisposeAsync();
    }
}

/// <summary>Webhooks of real SFTP sessions (#66): a signed POST per upload, and a pre-upload webhook that refuses an upload.</summary>
public sealed class WebhookEndToEndTests : IClassFixture<WebhookServerFixture>
{
    private readonly WebhookServerFixture _server;

    public WebhookEndToEndTests(WebhookServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task An_upload_triggers_exactly_one_signed_POST()
    {
        var path = _server.CreateUniqueDirectory("wh") + "/upload.bin";
        using (var client = _server.Connect())
        {
            using var stream = new MemoryStream(new byte[2048]);
            client.UploadFile(stream, path);
        }

        bool ForThisFile(ReceivedRequest r) => r.Path == "/uploads" && r.Json.GetProperty("virtual_path").GetString() == path;
        var request = Assert.Single(await _server.Receiver.WaitForAsync(1, ForThisFile));
        await Task.Delay(200, TestContext.Current.CancellationToken); // no second request comes later
        Assert.Single(_server.Receiver.Requests, ForThisFile);
        Assert.Equal("POST", request.Method);
        Assert.Equal("File.Upload", request.Header(WebhookSignature.EventHeader));
        Assert.True(WebhookSignature.Verify(WebhookServerFixture.Secret, request.Header(WebhookSignature.SignatureHeader), request.Body,
            DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5)));
        Assert.Equal(2048, request.Json.GetProperty("file_size").GetInt64());
        Assert.Equal(_server.Username, request.Json.GetProperty("username").GetString());
        Assert.Equal(1, request.Json.GetProperty("status").GetInt32());
        Assert.Equal("upload", request.Json.GetProperty("action").GetString());
        Assert.Equal("127.0.0.1", request.Json.GetProperty("ip").GetString());
        Assert.DoesNotContain(_server.Password, request.Body);
        await _server.Webhooks.WaitForDeliveriesAsync(_server.UploadWebhookId,
            d => d.Any(x => x.Payload.Contains(path, StringComparison.Ordinal) && x.Status == WebhookDeliveryStatus.Delivered));
    }

    [Fact]
    public void A_pre_upload_webhook_that_answers_403_refuses_the_upload_with_its_message()
    {
        var path = _server.CreateUniqueDirectory("wh") + "/denied.txt";

        using (var client = _server.Connect())
        {
            using var stream = new MemoryStream([1, 2, 3]);
            var error = Assert.Throws<SftpPermissionDeniedException>(() => client.UploadFile(stream, path));
            Assert.Contains(WebhookServerFixture.ScannerMessage, error.Message);
        }

        Assert.False(File.Exists(_server.PhysicalPath(path)));
        Assert.Contains(_server.Receiver.Requests, r => r.Path == "/scanner" && r.Json.GetProperty("virtual_path").GetString() == path);
    }

    [Fact]
    public void A_pre_upload_webhook_that_does_not_answer_within_its_timeout_refuses_the_upload()
    {
        var path = _server.CreateUniqueDirectory("wh") + "/slow.txt";
        var watch = Stopwatch.StartNew();

        using (var client = _server.Connect())
        {
            using var stream = new MemoryStream([1, 2, 3]);
            Assert.Throws<SftpPermissionDeniedException>(() => client.UploadFile(stream, path));
        }

        Assert.False(File.Exists(_server.PhysicalPath(path)));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(15), $"The upload waited {watch.Elapsed} for a webhook with a 1 s timeout.");
    }

    [Fact]
    public async Task OpenSSH_put_fails_with_permission_denied_when_the_pre_upload_webhook_answers_403()
    {
        OpenSshSftp.SkipIfUnavailable();
        var local = Path.Combine(_server.TempDirectory, "local-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(local);
        File.WriteAllBytes(Path.Combine(local, "denied.bin"), [1, 2, 3]);
        var directory = _server.CreateUniqueDirectory("ossh-wh");

        var result = await OpenSshSftp.RunAsync(_server, local, "cd " + directory, $"put {OpenSshSftp.Quote(Path.Combine(local, "denied.bin"))} denied.bin", "pwd");

        Assert.False(File.Exists(_server.PhysicalPath(directory + "/denied.bin")), result.ToString());
        Assert.Contains("Permission denied", result.AllOutput, StringComparison.OrdinalIgnoreCase);
    }
}
