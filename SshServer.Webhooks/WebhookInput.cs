using SshServer.Interfaces.Webhooks;

namespace SshServer.Webhooks;

/// <summary>A webhook as the admin UI (and later the REST API, #67) gives it to <see cref="WebhookAdministrationService"/>.</summary>
public sealed record WebhookInput
{
    /// <summary>Null: a new webhook.</summary>
    public int? Id { get; init; }

    public string Name { get; init; } = string.Empty;

    public string Url { get; init; } = string.Empty;

    public string Method { get; init; } = Webhook.MethodPost;

    /// <summary>A new secret; null or empty keeps the stored one.</summary>
    public string? NewSecret { get; init; }

    /// <summary>Removes the stored secret (the requests then have no signature).</summary>
    public bool RemoveSecret { get; init; }

    public IReadOnlyDictionary<string, string> Headers { get; init; } = new Dictionary<string, string>();

    public IReadOnlyList<string> EventTypes { get; init; } = [];

    public IReadOnlyList<string> Users { get; init; } = [];

    public string? PathGlob { get; init; }

    public bool Sync { get; init; }

    public bool FailOpen { get; init; }

    public int TimeoutSeconds { get; init; } = Webhook.DefaultTimeoutSeconds;

    public bool Enabled { get; init; } = true;

    public static WebhookInput From(Webhook webhook) => new()
    {
        Id = webhook.Id,
        Name = webhook.Name,
        Url = webhook.Url,
        Method = webhook.Method,
        Headers = new Dictionary<string, string>(webhook.Headers),
        EventTypes = [.. webhook.EventTypes],
        Users = [.. webhook.Users],
        PathGlob = webhook.PathGlob,
        Sync = webhook.Sync,
        FailOpen = webhook.FailOpen,
        TimeoutSeconds = webhook.TimeoutSeconds,
        Enabled = webhook.Enabled,
    };
}
