namespace SshServer.Interfaces.Webhooks;

/// <summary>
/// An HTTP endpoint that gets events (#66). The webhooks plug-in (<c>SshServer.Webhooks</c>, <c>AddWebhooks()</c>) sends
/// them; the settings store keeps this entity through <see cref="IWebhookStore"/>. Rules of the fields are in the
/// webhooks plug-in (<c>WebhookValidator</c>).
/// </summary>
public sealed class Webhook
{
    public const string MethodPost = "POST";
    public const string MethodPut = "PUT";
    public const int DefaultTimeoutSeconds = 10;
    public const int MaxTimeoutSeconds = 30;

    public int Id { get; set; }

    /// <summary>A unique name (case-insensitive), for the admin UI and the log.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>The endpoint: <c>https://</c>, or <c>http://</c> to a loopback or private address when the operator allows it.</summary>
    public string Url { get; set; } = string.Empty;

    /// <summary><see cref="MethodPost"/> (default) or <see cref="MethodPut"/>.</summary>
    public string Method { get; set; } = MethodPost;

    /// <summary>
    /// The HMAC secret of the signature, encrypted by the webhooks plug-in (never the plain text). Null: the requests
    /// have no signature.
    /// </summary>
    public string? ProtectedSecret { get; set; }

    /// <summary>Static headers of every request, for example an API key of the receiver.</summary>
    public Dictionary<string, string> Headers { get; set; } = new();

    /// <summary>
    /// The events, as "Category.Type" (for example "File.Upload", "Auth.LoginFailed"). Empty: every event except the
    /// <c>Pre*</c> events, which must be named.
    /// </summary>
    public List<string> EventTypes { get; set; } = new();

    /// <summary>Only the events of these users (case-insensitive). Empty: every user, and the events without a user.</summary>
    public List<string> Users { get; set; } = new();

    /// <summary>
    /// Only the file events whose virtual path (or target path) matches this glob: <c>*</c> within a directory,
    /// <c>**</c> over directories, <c>?</c> one character. Null or empty: every path, and the other events.
    /// </summary>
    public string? PathGlob { get; set; }

    /// <summary>
    /// True: the webhook decides synchronously whether the operation of a <c>Pre*</c> event may run (2xx allows, 403
    /// denies). Only for <c>Pre*</c> events.
    /// </summary>
    public bool Sync { get; set; }

    /// <summary>For a <see cref="Sync"/> webhook: an error or a timeout allows the operation (default: it is denied).</summary>
    public bool FailOpen { get; set; }

    /// <summary>The time for one request, 1 to <see cref="MaxTimeoutSeconds"/> seconds.</summary>
    public int TimeoutSeconds { get; set; } = DefaultTimeoutSeconds;

    public bool Enabled { get; set; } = true;

    /// <summary>
    /// True: the webhook gets no events of its own; only the "Webhook" action of an event rule (#68) sends to it, and its
    /// event, user and path filters are not used. Never together with <see cref="Sync"/>.
    /// </summary>
    public bool OnlyForEventRules { get; set; }
}
