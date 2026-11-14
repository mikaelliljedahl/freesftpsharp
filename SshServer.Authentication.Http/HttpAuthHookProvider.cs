using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Authentication;
using SshServer.Webhooks;

namespace SshServer.Authentication.Http;

/// <summary>
/// The external HTTP authentication hook (issue #64): a <c>POST</c> with the credential as JSON
/// (<see cref="HttpAuthHookPayload"/>), signed with <see cref="WebhookSignature"/> when a secret is set. The service
/// answers <c>200</c> with a user (it is created or updated with it), <c>204</c> when it does not know the user (the next
/// provider is asked), anything else refuses. No answer within the timeout, a redirect, an answer over 64 KiB or one that
/// is not a valid user refuse too (fail closed). The password is never logged.
/// </summary>
public sealed class HttpAuthHookProvider : IAuthenticationProvider
{
    public const string ProviderName = "http";
    public const string HttpClientName = "FreeSftpSharp.AuthHook";
    public const string UserAgent = "FreeSftpSharp-AuthHook";
    public const int MaxResponseBytes = 64 * 1024;

    private readonly IHttpClientFactory _clients;
    private readonly HttpAuthHookOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private int _legacyWarned;

    public HttpAuthHookProvider(IHttpClientFactory clients, IOptions<HttpAuthHookOptions> options, TimeProvider time, ILogger<HttpAuthHookProvider> logger)
    {
        _clients = clients;
        _options = options.Value;
        _time = time;
        _logger = logger;
    }

    public string Name => ProviderName;

    public async ValueTask<AuthResult> AuthenticateAsync(AuthRequest request, CancellationToken ct)
    {
        if (request.Password == null && (request.PublicKey == null || !_options.PublicKeys))
            return AuthResult.NotHandled;

        var body = HttpAuthHookPayload.CreateRequest(request);
        using var message = new HttpRequestMessage(HttpMethod.Post, _options.Url)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        message.Headers.UserAgent.Add(new ProductInfoHeaderValue(UserAgent, null));
        if (!string.IsNullOrEmpty(_options.Secret))
            message.Headers.TryAddWithoutValidation(WebhookSignature.SignatureHeader,
                WebhookSignature.Create(_options.Secret, _time.GetUtcNow().ToUnixTimeSeconds(), body));

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_options.TimeoutSeconds, 1, HttpAuthHookOptions.MaxTimeoutSeconds)));
        try
        {
            using var response = await _clients.CreateClient(HttpClientName).SendAsync(message, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            switch (response.StatusCode)
            {
                case HttpStatusCode.NoContent:
                    return AuthResult.NotHandled;
                case HttpStatusCode.OK:
                    var answer = await ReadLimitedAsync(response.Content, timeout.Token);
                    if (answer == null)
                        return Refuse(request, $"the answer is larger than {MaxResponseBytes / 1024} KiB");
                    try
                    {
                        var user = HttpAuthHookPayload.ParseUser(answer, request.Username, out var legacyFormat);
                        if (legacyFormat)
                            WarnLegacyFormat();
                        return AuthResult.Success(user);
                    }
                    catch (FormatException ex)
                    {
                        return Refuse(request, "the answer is not a valid user: " + ex.Message);
                    }
                default:
                    _logger.LogInformation("The authentication hook refused the {Request}: HTTP {Status}.", request.ToString(), (int)response.StatusCode);
                    return AuthResult.Failure($"the authentication hook answered HTTP {(int)response.StatusCode}");
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return Refuse(request, $"the authentication hook did not answer within {_options.TimeoutSeconds} s");
        }
        catch (HttpRequestException ex)
        {
            return Refuse(request, "the authentication hook cannot be reached: " + ex.Message);
        }
    }

    /// <summary>Once per provider (one per process): the snake_case answer is deprecated (#136).</summary>
    private void WarnLegacyFormat()
    {
        if (Interlocked.Exchange(ref _legacyWarned, 1) == 0)
            _logger.LogWarning("The authentication hook answered in the deprecated snake_case format (primary_group, allowed_ips, max_sessions). "
                + "Answer with the camelCase names of the REST API user (primaryGroup, whitelistedIps, maxSessions); the old format will be removed in the next release. See docs/AUTHENTICATION.md.");
    }

    private AuthResult Refuse(AuthRequest request, string reason)
    {
        _logger.LogWarning("The {Request} is refused: {Reason}.", request.ToString(), reason);
        return AuthResult.Failure(reason);
    }

    /// <summary>The body as text, or null when it is larger than <see cref="MaxResponseBytes"/>.</summary>
    private static async Task<string?> ReadLimitedAsync(HttpContent content, CancellationToken ct)
    {
        if (content.Headers.ContentLength > MaxResponseBytes)
            return null;
        await using var stream = await content.ReadAsStreamAsync(ct);
        var buffer = new byte[MaxResponseBytes + 1];
        var total = 0;
        int read;
        while (total < buffer.Length && (read = await stream.ReadAsync(buffer.AsMemory(total), ct)) > 0)
            total += read;
        return total > MaxResponseBytes ? null : Encoding.UTF8.GetString(buffer, 0, total);
    }
}
