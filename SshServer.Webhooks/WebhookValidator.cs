using System.Net;
using System.Net.Sockets;
using SshServer.Interfaces.Webhooks;
using SshServer.Interfaces.Events;

namespace SshServer.Webhooks;

/// <summary>The rules of a webhook. Returns the errors as texts for the admin UI; an empty list: valid.</summary>
public static class WebhookValidator
{
    public const int MaxNameLength = 100;
    public const int MinSecretLength = 16;

    private static readonly HashSet<string> ReservedHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Content-Type", "Content-Length", "Content-Encoding", "Host", "Transfer-Encoding", "Connection", "Expect", "Upgrade",
        "User-Agent", WebhookSignature.SignatureHeader, WebhookSignature.EventHeader, WebhookSignature.DeliveryHeader,
    };

    public static IReadOnlyList<string> Validate(WebhookInput input, WebhookOptions options)
    {
        var errors = new List<string>();
        var name = input.Name?.Trim() ?? string.Empty;
        if (name.Length == 0)
            errors.Add("Enter a name.");
        else if (name.Length > MaxNameLength)
            errors.Add($"The name can have at most {MaxNameLength} characters.");

        if (ValidateUrl(input.Url, options) is { } urlError)
            errors.Add(urlError);

        if (input.Method is not (Webhook.MethodPost or Webhook.MethodPut))
            errors.Add("The method must be POST or PUT.");

        if (input.TimeoutSeconds is < 1 or > Webhook.MaxTimeoutSeconds)
            errors.Add($"The timeout must be 1 to {Webhook.MaxTimeoutSeconds} seconds.");

        if (!string.IsNullOrEmpty(input.NewSecret) && input.NewSecret.Length < MinSecretLength)
            errors.Add($"The secret must have at least {MinSecretLength} characters.");

        foreach (var (header, value) in input.Headers)
        {
            if (string.IsNullOrWhiteSpace(header) || header.Any(c => c <= ' ' || c >= 127 || c == ':'))
                errors.Add($"The header name '{header}' is not valid.");
            else if (ReservedHeaders.Contains(header) || header.StartsWith("X-FreeSftpSharp-", StringComparison.OrdinalIgnoreCase))
                errors.Add($"The header {header} is set by the server.");
            if (value.Any(c => c is '\r' or '\n'))
                errors.Add($"The value of the header {header} cannot have a line break.");
        }

        var unknown = input.EventTypes.Where(e => !EventNames.IsKnown(e)).ToArray();
        if (unknown.Length > 0)
            errors.Add("Unknown events: " + string.Join(", ", unknown) + ".");

        if (input.Sync && input.OnlyForEventRules)
            errors.Add("A webhook only for event rules cannot be synchronous.");
        else if (input.Sync)
        {
            if (input.EventTypes.Count == 0 || input.EventTypes.Any(e => !EventNames.PreEvents.Contains(e)))
                errors.Add("A synchronous webhook is only for the events File.PreUpload, File.PreDownload and File.PreDelete. Select one or more of them, and no others.");
        }
        else if (input.FailOpen)
        {
            errors.Add("Fail open is only for a synchronous webhook.");
        }

        if (!string.IsNullOrWhiteSpace(input.PathGlob) && !input.PathGlob.Trim().StartsWith('/'))
            errors.Add("The path filter is a virtual path and starts with '/', for example /incoming/**.");

        if (input.Users.Any(string.IsNullOrWhiteSpace))
            errors.Add("A user name in the filter is empty.");

        return errors;
    }

    /// <summary>The URL rule: absolute, <c>https://</c> (or <c>http://</c> to a loopback or private address when allowed), no credentials.</summary>
    public static string? ValidateUrl(string? url, WebhookOptions options)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
            return "Enter an absolute URL, for example https://hooks.example.com/sftp.";
        if (!string.IsNullOrEmpty(uri.UserInfo))
            return "The URL cannot have a user name or password. Put a credential in a header.";
        if (uri.Scheme == Uri.UriSchemeHttps)
            return null;
        if (uri.Scheme != Uri.UriSchemeHttp)
            return "The URL must start with https://.";
        if (!IsLoopbackOrPrivate(uri))
            return "An http:// URL is only allowed to a loopback or private address. Use https://.";
        if (!options.AllowInsecureWebhooks)
            return $"An http:// URL needs {WebhookOptions.SectionName}:{nameof(WebhookOptions.AllowInsecureWebhooks)}=true in the configuration. Use https://.";
        return null;
    }

    /// <summary>localhost, a loopback address or a private address (10/8, 172.16/12, 192.168/16, fc00::/7).</summary>
    public static bool IsLoopbackOrPrivate(Uri uri)
    {
        var host = uri.Host;
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
            return true;
        if (!IPAddress.TryParse(host.Trim('[', ']'), out var address))
            return false;
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address))
            return true;
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return address.IsIPv6UniqueLocal;
        var b = address.GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168);
    }
}
