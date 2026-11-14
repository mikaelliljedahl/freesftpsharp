namespace SshServer.Interfaces.Audit;

/// <summary>One row of the audit log: an <see cref="Events.IEvent"/> in a flat form (see <see cref="AuditEntryMapper"/>).</summary>
public class AuditEntry
{
    public long Id { get; set; }

    /// <summary>When the event happened, UTC.</summary>
    public DateTime TimestampUtc { get; set; }

    /// <summary>The <see cref="Events.EventCategory"/>, for example "File".</summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>The type within the category, for example "Upload".</summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>Who made a change of a stored object (an admin, an API key, "self").</summary>
    public string? Actor { get; set; }

    public string? Username { get; set; }
    public string? RemoteIp { get; set; }
    public string? Protocol { get; set; }
    public string? SessionId { get; set; }

    /// <summary>The virtual path of a file event, or the name of a stored object.</summary>
    public string? Path { get; set; }

    /// <summary>The new path of a rename.</summary>
    public string? TargetPath { get; set; }

    /// <summary>The file size in bytes.</summary>
    public long? Size { get; set; }

    /// <summary>The duration of the operation in milliseconds.</summary>
    public long? ElapsedMilliseconds { get; set; }

    /// <summary>"Ok", "Error", "Denied", "QuotaExceeded" for file events, "Ok" or "Failed" for the others.</summary>
    public string Status { get; set; } = string.Empty;

    public string? Message { get; set; }

    /// <summary>The other values of the event as JSON, without secrets.</summary>
    public string? Details { get; set; }
}
