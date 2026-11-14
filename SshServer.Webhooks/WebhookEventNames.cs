using SshServer.Interfaces.Events;

namespace SshServer.Webhooks;

/// <summary>The names of the events in the filter of a webhook and in the payload: "Category.Type", for example "File.Upload".</summary>
public static class WebhookEventNames
{
    /// <summary>Every event name, grouped by category, for the admin UI and the validation.</summary>
    public static IReadOnlyList<(EventCategory Category, IReadOnlyList<string> Names)> Groups { get; } =
    [
        (EventCategory.File, Qualify(EventCategory.File, Enum.GetNames<FileEventType>())),
        (EventCategory.Auth, Qualify(EventCategory.Auth, Enum.GetNames<AuthEventType>())),
        (EventCategory.Provider, Qualify(EventCategory.Provider, Enum.GetNames<ProviderAction>())),
        (EventCategory.System, Qualify(EventCategory.System, Enum.GetNames<SystemEventType>())),
    ];

    /// <summary>The events that a synchronous webhook can decide (<see cref="FileEvent.IsPreEvent"/>).</summary>
    public static IReadOnlySet<string> PreEvents { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        Of(EventCategory.File, nameof(FileEventType.PreUpload)),
        Of(EventCategory.File, nameof(FileEventType.PreDownload)),
        Of(EventCategory.File, nameof(FileEventType.PreDelete)),
    };

    private static readonly HashSet<string> All = new(Groups.SelectMany(g => g.Names), StringComparer.OrdinalIgnoreCase);

    public static string Of(IEvent @event) => Of(@event.Category, @event.TypeName);

    public static string Of(EventCategory category, string typeName) => $"{category}.{typeName}";

    public static bool IsKnown(string name) => All.Contains(name);

    /// <summary>The name with the spelling of the enum, for a name that <see cref="IsKnown"/>.</summary>
    public static string Canonical(string name) => All.TryGetValue(name, out var canonical) ? canonical : name;

    private static IReadOnlyList<string> Qualify(EventCategory category, string[] names) => names.Select(n => Of(category, n)).ToArray();
}
