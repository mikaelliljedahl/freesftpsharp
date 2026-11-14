using SshServer.Webhooks;

namespace FreeSftpSharp.Tests.Webhooks;

/// <summary>The rules of a webhook: https, http only to loopback or private addresses when allowed, sync only for Pre* events.</summary>
public sealed class WebhookValidatorTests
{
    private static readonly WebhookOptions Strict = new();
    private static readonly WebhookOptions Insecure = new() { AllowInsecureWebhooks = true };

    private static WebhookInput Valid => new() { Name = "hook", Url = "https://hooks.example.com/sftp" };

    [Fact]
    public void A_simple_https_webhook_is_valid()
    {
        Assert.Empty(WebhookValidator.Validate(Valid, Strict));
    }

    [Theory]
    [InlineData("http://127.0.0.1:8080/x")]
    [InlineData("http://localhost/x")]
    [InlineData("http://[::1]/x")]
    [InlineData("http://10.1.2.3/x")]
    [InlineData("http://172.20.0.5/x")]
    [InlineData("http://192.168.1.10/x")]
    [InlineData("http://[fd00::5]/x")]
    public void Http_to_a_loopback_or_private_address_needs_AllowInsecureWebhooks(string url)
    {
        Assert.NotNull(WebhookValidator.ValidateUrl(url, Strict));
        Assert.Null(WebhookValidator.ValidateUrl(url, Insecure));
    }

    [Theory]
    [InlineData("http://hooks.example.com/x")]
    [InlineData("http://8.8.8.8/x")]
    [InlineData("http://172.32.0.1/x")]
    [InlineData("ftp://192.168.1.1/x")]
    [InlineData("https://user:pass@hooks.example.com/x")]
    [InlineData("/relative")]
    [InlineData("")]
    public void Other_urls_are_refused_also_with_AllowInsecureWebhooks(string url)
    {
        Assert.NotNull(WebhookValidator.ValidateUrl(url, Insecure));
    }

    [Fact]
    public void A_sync_webhook_must_name_only_Pre_events_and_fail_open_needs_sync()
    {
        Assert.NotEmpty(WebhookValidator.Validate(Valid with { Sync = true }, Strict));
        Assert.NotEmpty(WebhookValidator.Validate(Valid with { Sync = true, EventTypes = ["File.PreUpload", "File.Upload"] }, Strict));
        Assert.Empty(WebhookValidator.Validate(Valid with { Sync = true, FailOpen = true, EventTypes = ["File.PreUpload", "File.PreDelete"] }, Strict));
        Assert.NotEmpty(WebhookValidator.Validate(Valid with { FailOpen = true }, Strict));
    }

    [Fact]
    public void Timeouts_methods_events_headers_secrets_and_paths_are_checked()
    {
        Assert.NotEmpty(WebhookValidator.Validate(Valid with { TimeoutSeconds = 0 }, Strict));
        Assert.NotEmpty(WebhookValidator.Validate(Valid with { TimeoutSeconds = 31 }, Strict));
        Assert.Empty(WebhookValidator.Validate(Valid with { TimeoutSeconds = 30, Method = "PUT" }, Strict));
        Assert.NotEmpty(WebhookValidator.Validate(Valid with { Method = "GET" }, Strict));
        Assert.NotEmpty(WebhookValidator.Validate(Valid with { EventTypes = ["File.Nothing"] }, Strict));
        Assert.Empty(WebhookValidator.Validate(Valid with { EventTypes = ["file.upload", "Auth.LoginFailed", "Provider.Delete"] }, Strict));
        Assert.NotEmpty(WebhookValidator.Validate(Valid with { Headers = new Dictionary<string, string> { ["X-FreeSftpSharp-Signature"] = "x" } }, Strict));
        Assert.NotEmpty(WebhookValidator.Validate(Valid with { Headers = new Dictionary<string, string> { ["Content-Type"] = "text/plain" } }, Strict));
        Assert.NotEmpty(WebhookValidator.Validate(Valid with { Headers = new Dictionary<string, string> { ["X-Key"] = "a\r\nInjected: 1" } }, Strict));
        Assert.Empty(WebhookValidator.Validate(Valid with { Headers = new Dictionary<string, string> { ["Authorization"] = "Bearer abc" } }, Strict));
        Assert.NotEmpty(WebhookValidator.Validate(Valid with { NewSecret = "short" }, Strict));
        Assert.NotEmpty(WebhookValidator.Validate(Valid with { PathGlob = "incoming/*" }, Strict));
        Assert.NotEmpty(WebhookValidator.Validate(Valid with { Name = " " }, Strict));
    }
}
