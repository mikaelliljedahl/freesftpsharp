namespace SshServer.Interfaces.Events;

/// <summary>The kind of an <see cref="IEvent"/>.</summary>
public enum EventCategory
{
    /// <summary>A file operation (<see cref="FileEvent"/>).</summary>
    File,

    /// <summary>A login, logout or ban (<see cref="AuthEvent"/>).</summary>
    Auth,

    /// <summary>A change of a stored object, for example a user (<see cref="ProviderEvent"/>).</summary>
    Provider,

    /// <summary>Something the server itself did (<see cref="SystemEvent"/>).</summary>
    System,
}

/// <summary>
/// Something that happened in the server. Every protocol and every part of the server produces these events, and every
/// consumer (audit log, webhooks, event rules, metrics, the UI) reads them from <see cref="IEventBus"/>. An event is an
/// immutable record and never contains a secret (password, key, token).
/// </summary>
public interface IEvent
{
    EventCategory Category { get; }

    /// <summary>The type within the category, for example "Upload" or "LoginFailed".</summary>
    string TypeName { get; }

    /// <summary>When the event happened.</summary>
    DateTimeOffset Timestamp { get; }
}
