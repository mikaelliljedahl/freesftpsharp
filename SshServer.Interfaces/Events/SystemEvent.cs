namespace SshServer.Interfaces.Events;

/// <summary>The type of a <see cref="SystemEvent"/>.</summary>
public enum SystemEventType
{
    Started,
    Stopping,
    CertificateRenewed,
    ScheduledJobRan,

    /// <summary>The server closed the open sessions of a user (the user expired, was disabled or removed).</summary>
    SessionsClosed,
}

/// <summary>Something the server itself did.</summary>
/// <param name="Type">What happened.</param>
public sealed record SystemEvent(SystemEventType Type) : IEvent
{
    public EventCategory Category => EventCategory.System;

    public string TypeName => Type.ToString();

    public DateTimeOffset Timestamp { get; init; }

    /// <summary>The part of the server, for example "SFTP" or "AuditRetention".</summary>
    public string? Source { get; init; }

    public string? Message { get; init; }
}
