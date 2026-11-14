namespace SshServer.Interfaces.Webhooks;

/// <summary>The state of a <see cref="WebhookDelivery"/>.</summary>
public enum WebhookDeliveryStatus
{
    /// <summary>Waits for its first or next attempt (<see cref="WebhookDelivery.NextAttemptUtc"/>).</summary>
    Pending,

    /// <summary>The receiver answered 2xx (a synchronous webhook: it answered 2xx or 403).</summary>
    Delivered,

    /// <summary>A synchronous delivery that failed (error, timeout, other status). It is not sent again.</summary>
    Failed,

    /// <summary>Every attempt failed; it is not sent again unless an admin redelivers it.</summary>
    DeadLetter,
}

/// <summary>
/// One event for one webhook: a row of the outbox. The webhooks plug-in writes it when the event happens and sends it
/// in the background until the receiver accepts it (at-least-once). The row survives a restart.
/// </summary>
public sealed class WebhookDelivery
{
    public long Id { get; set; }

    /// <summary>The id of the delivery in the <c>X-FreeSftpSharp-Delivery</c> header; the same for every attempt.</summary>
    public Guid DeliveryId { get; set; }

    public int WebhookId { get; set; }

    /// <summary>The <c>event_id</c> of the payload; the same for every webhook of the event.</summary>
    public Guid EventId { get; set; }

    /// <summary>"Category.Type" of the event, for example "File.Upload".</summary>
    public string EventType { get; set; } = string.Empty;

    /// <summary>The JSON body without the attempt number (it is set for each attempt).</summary>
    public string Payload { get; set; } = string.Empty;

    /// <summary>True for a delivery of a synchronous webhook (a record of the answer; it is never sent again).</summary>
    public bool Sync { get; set; }

    public WebhookDeliveryStatus Status { get; set; }

    /// <summary>The attempts so far.</summary>
    public int Attempts { get; set; }

    public DateTime CreatedUtc { get; set; }

    /// <summary>When the next attempt is due; null when the delivery is finished.</summary>
    public DateTime? NextAttemptUtc { get; set; }

    public DateTime? LastAttemptUtc { get; set; }

    /// <summary>The HTTP status of the last answer; null when there was no answer (error, timeout).</summary>
    public int? LastStatusCode { get; set; }

    /// <summary>Why the last attempt failed.</summary>
    public string? LastError { get; set; }

    /// <summary>The start of the last response body, at most 4 KiB.</summary>
    public string? ResponseExcerpt { get; set; }

    /// <summary>The node that sends the delivery now (#75); null when nobody has it.</summary>
    public string? LeaseOwner { get; set; }

    /// <summary>Until when <see cref="LeaseOwner"/> has it. After that another node may take it (the owner stopped).</summary>
    public DateTime? LeaseUntilUtc { get; set; }
}
