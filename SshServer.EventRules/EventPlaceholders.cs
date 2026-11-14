using System.Globalization;
using System.Text.Json;
using SshServer.Interfaces;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Storage;

namespace SshServer.EventRules;

/// <summary>The values of the placeholders of one run (<see cref="EventTemplate"/>).</summary>
public static class EventPlaceholders
{
    /// <summary>The names with a short description, for the admin UI and docs/EVENT-RULES.md.</summary>
    public static IReadOnlyList<(string Name, string Description)> Known { get; } =
    [
        ("Rule", "the name of the rule"),
        ("Event", "the event, for example File.Upload; Schedule or OnDemand"),
        ("Username", "the user"),
        ("VirtualPath", "the virtual path of the file"),
        ("VirtualTargetPath", "the new path of a rename or copy"),
        ("Name", "the file name (last part of the path)"),
        ("Dir", "the directory of the file"),
        ("FileSize", "the size in bytes"),
        ("Status", "Ok, Error, QuotaExceeded or Denied"),
        ("Protocol", "the protocol of the client, for example SFTP"),
        ("Ip", "the address of the client"),
        ("Timestamp", "the time of the event, ISO 8601 UTC"),
        ("Date", "the date of the run, yyyy-MM-dd UTC"),
        ("Message", "the message of the event"),
        ("ObjectType", "the object of a provider event, for example User"),
        ("ObjectName", "the name of that object"),
        ("ObjectData", "that object as JSON, without secrets"),
        ("RetentionDeleted", "after a Retention action: the number of removed files"),
        ("RetentionReport", "after a Retention action: one line per folder"),
    ];

    private static readonly JsonSerializerOptions ObjectJson = new() { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    /// <summary>The values of the run; <paramref name="values"/> (set by earlier actions) win over the event values.</summary>
    public static IReadOnlyDictionary<string, string> For(EventRule rule, IEvent? @event, string trigger, User? user, DateTimeOffset now,
        IDictionary<string, string> values)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Rule"] = rule.Name,
            ["Event"] = trigger,
            ["Date"] = now.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            ["Timestamp"] = (@event?.Timestamp ?? now).UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
        };
        if (user != null)
            result["Username"] = user.Username;

        switch (@event)
        {
            case FileEvent file:
                result["Username"] = file.Username;
                result["VirtualPath"] = file.VirtualPath;
                var normalized = VirtualPath.Normalize(file.VirtualPath);
                result["Name"] = VirtualPath.GetName(normalized);
                result["Dir"] = VirtualPath.GetParent(normalized);
                if (file.VirtualTargetPath != null)
                    result["VirtualTargetPath"] = file.VirtualTargetPath;
                if (file.FileSize is { } size)
                    result["FileSize"] = size.ToString(CultureInfo.InvariantCulture);
                result["Status"] = file.Status.ToString();
                result["Protocol"] = file.Protocol;
                Add(result, "Ip", file.RemoteIp);
                Add(result, "Message", file.Message);
                break;

            case AuthEvent auth:
                Add(result, "Username", auth.Username);
                result["Protocol"] = auth.Protocol;
                Add(result, "Ip", auth.RemoteIp);
                Add(result, "Message", auth.Reason);
                break;

            case ProviderEvent provider:
                result["ObjectType"] = provider.ObjectType.ToString();
                result["ObjectName"] = provider.ObjectName;
                if (provider.Object != null)
                    result["ObjectData"] = JsonSerializer.Serialize(provider.Object, provider.Object.GetType(), ObjectJson);
                break;

            case SystemEvent system:
                Add(result, "Message", system.Message);
                break;
        }

        foreach (var (key, value) in values)
            result[key] = value;
        return result;
    }

    private static void Add(Dictionary<string, string> values, string key, string? value)
    {
        if (!string.IsNullOrEmpty(value))
            values[key] = value;
    }
}
