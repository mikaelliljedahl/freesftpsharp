using System.Net.Http.Headers;
using System.Text;
using SshServer.Interfaces.Webhooks;

namespace SshServer.Webhooks;

/// <summary>The answer to one webhook request.</summary>
/// <param name="StatusCode">The HTTP status; null when there was no answer.</param>
/// <param name="Body">The start of the response body, at most <see cref="WebhookSender.MaxResponseBytes"/> bytes.</param>
/// <param name="Error">Why there was no answer (timeout, connection error), or null.</param>
public sealed record WebhookResponse(int? StatusCode, string? Body, string? Error)
{
    public bool IsSuccess => StatusCode is >= 200 and < 300;

    /// <summary>A short text for the log and the deliveries list.</summary>
    public string Describe() => Error ?? $"HTTP {StatusCode}";
}

/// <summary>
/// Sends one webhook request: the JSON body with the event, delivery and signature headers, within the timeout of the
/// webhook. It never follows a redirect (the HTTP client has redirects off; a 3xx is a failure) and reads at most 4 KiB
/// of the answer.
/// </summary>
public sealed class WebhookSender
{
    public const string HttpClientName = "FreeSftpSharp.Webhooks";
    public const int MaxResponseBytes = 4096;
    public const string UserAgent = "FreeSftpSharp-Webhooks";

    private readonly IHttpClientFactory _clients;
    private readonly TimeProvider _time;

    public WebhookSender(IHttpClientFactory clients, TimeProvider time)
    {
        _clients = clients;
        _time = time;
    }

    /// <summary>Sends the body. Throws <see cref="OperationCanceledException"/> only when <paramref name="ct"/> is canceled.</summary>
    public async Task<WebhookResponse> SendAsync(ActiveWebhook webhook, Guid deliveryId, string eventName, string body, CancellationToken ct)
    {
        if (webhook.Error != null)
            return new WebhookResponse(null, null, webhook.Error);

        var definition = webhook.Definition;
        using var request = new HttpRequestMessage(new HttpMethod(definition.Method), definition.Url)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        foreach (var (name, value) in definition.Headers)
            request.Headers.TryAddWithoutValidation(name, value);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue(UserAgent, null));
        request.Headers.TryAddWithoutValidation(WebhookSignature.EventHeader, eventName);
        request.Headers.TryAddWithoutValidation(WebhookSignature.DeliveryHeader, deliveryId.ToString());
        if (webhook.Secret != null)
            request.Headers.TryAddWithoutValidation(WebhookSignature.SignatureHeader,
                WebhookSignature.Create(webhook.Secret, _time.GetUtcNow().ToUnixTimeSeconds(), body));

        // The timeout is wall-clock time (network I/O), not the clock of the events.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(definition.TimeoutSeconds, 1, Webhook.MaxTimeoutSeconds)));
        try
        {
            var client = _clients.CreateClient(HttpClientName);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            var excerpt = await ReadExcerptAsync(response.Content, timeout.Token);
            return new WebhookResponse((int)response.StatusCode, excerpt, null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new WebhookResponse(null, null, $"No answer within {definition.TimeoutSeconds} s.");
        }
        catch (HttpRequestException ex)
        {
            return new WebhookResponse(null, null, "The request failed: " + ex.Message);
        }
    }

    private static async Task<string?> ReadExcerptAsync(HttpContent content, CancellationToken ct)
    {
        await using var stream = await content.ReadAsStreamAsync(ct);
        var buffer = new byte[MaxResponseBytes];
        var total = 0;
        int read;
        while (total < buffer.Length && (read = await stream.ReadAsync(buffer.AsMemory(total), ct)) > 0)
            total += read;
        return total == 0 ? null : Encoding.UTF8.GetString(buffer, 0, total);
    }
}
