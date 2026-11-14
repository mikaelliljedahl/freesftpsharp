using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using SshServer.Interfaces.Events;

namespace SshServer.Webhooks;

/// <summary>
/// The JSON body of a webhook request: one event, its fields in snake_case, an <c>event_id</c> and the <c>attempt</c>.
/// The names follow the hook payload of SFTPGo where they overlap (<c>action</c>, <c>username</c>, <c>path</c>,
/// <c>virtual_path</c>, <c>file_size</c>, <c>status</c>, <c>protocol</c>, <c>ip</c>, <c>timestamp</c>, <c>elapsed</c>),
/// with the same values: <c>action</c> "upload", "pre-upload", "first-upload", "ssh_cmd", ...; <c>status</c> 1 ok,
/// 2 error, 3 quota exceeded (and 4 denied by a hook); <c>timestamp</c> in nanoseconds since 1970. Paths are virtual
/// paths; the payload has no secret. See docs/WEBHOOKS.md.
/// </summary>
public static class WebhookPayload
{
    private static readonly JsonSerializerOptions ObjectJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>The payload of <paramref name="event"/> with <c>attempt</c> 0; <see cref="WithAttempt"/> sets it.</summary>
    public static string Create(IEvent @event, Guid eventId)
    {
        var json = new JsonObject
        {
            ["event_id"] = eventId.ToString(),
            ["attempt"] = 0,
            ["event"] = WebhookEventNames.Of(@event),
            ["category"] = @event.Category.ToString().ToLowerInvariant(),
            ["action"] = Action(@event),
            ["timestamp"] = (@event.Timestamp - DateTimeOffset.UnixEpoch).Ticks * 100,
            ["time"] = @event.Timestamp.UtcDateTime.ToString("O"),
        };

        switch (@event)
        {
            case FileEvent file:
                Add(json, "username", file.Username);
                Add(json, "path", file.VirtualPath);
                Add(json, "virtual_path", file.VirtualPath);
                Add(json, "target_path", file.VirtualTargetPath);
                Add(json, "virtual_target_path", file.VirtualTargetPath);
                if (file.FileSize is { } size)
                    json["file_size"] = size;
                if (file.Elapsed is { } elapsed)
                    json["elapsed"] = (long)elapsed.TotalMilliseconds;
                json["status"] = Status(file.Status);
                json["status_text"] = file.Status.ToString();
                Add(json, "message", file.Message);
                Add(json, "protocol", file.Protocol);
                Add(json, "ip", file.RemoteIp);
                Add(json, "session_id", file.SessionId);
                Add(json, "storage_provider", file.Provider);
                if (file.OpenFlags is { } flags)
                    json["open_flags_text"] = flags.ToString();
                if (file.Metadata is { Count: > 0 } metadata)
                    json["metadata"] = JsonSerializer.SerializeToNode(metadata);
                break;

            case AuthEvent auth:
                Add(json, "username", auth.Username);
                Add(json, "ip", auth.RemoteIp);
                Add(json, "protocol", auth.Protocol);
                Add(json, "login_method", auth.Method);
                Add(json, "reason", auth.Reason);
                Add(json, "session_id", auth.SessionId);
                break;

            case ProviderEvent provider:
                json["object_type"] = provider.ObjectType.ToString().ToLowerInvariant();
                json["object_name"] = provider.ObjectName;
                Add(json, "actor", provider.Actor);
                if (provider.ChangedFields.Count > 0)
                    json["changed_fields"] = new JsonArray(provider.ChangedFields.Select(f => (JsonNode?)JsonValue.Create(f)).ToArray());
                if (provider.Object != null)
                    json["object"] = JsonSerializer.SerializeToNode(provider.Object, provider.Object.GetType(), ObjectJson);
                break;

            case SystemEvent system:
                Add(json, "source", system.Source);
                Add(json, "message", system.Message);
                break;

            case WebhookTestEvent test:
                json["source"] = "Webhooks";
                json["message"] = $"A test event for the webhook {test.WebhookName}.";
                break;
        }

        return json.ToJsonString();
    }

    /// <summary>The body of one attempt: the payload with its <c>attempt</c> number.</summary>
    public static string WithAttempt(string payload, int attempt)
    {
        var json = JsonNode.Parse(payload)!.AsObject();
        json["attempt"] = attempt;
        return json.ToJsonString();
    }

    /// <summary>The SFTPGo action name: "pre-upload", "first-upload", "ssh_cmd", "login-failed", ...</summary>
    public static string Action(IEvent @event)
    {
        if (@event is FileEvent { Type: FileEventType.SshCommand })
            return "ssh_cmd";
        var name = @event.TypeName;
        var builder = new StringBuilder(name.Length + 4);
        for (var i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (char.IsUpper(c) && i > 0)
                builder.Append('-');
            builder.Append(char.ToLowerInvariant(c));
        }
        return builder.ToString();
    }

    /// <summary>The SFTPGo status: 1 ok, 2 error, 3 quota exceeded; 4 (FreeSftpSharp) denied by a hook.</summary>
    public static int Status(FileEventStatus status) => status switch
    {
        FileEventStatus.Ok => 1,
        FileEventStatus.Error => 2,
        FileEventStatus.QuotaExceeded => 3,
        FileEventStatus.Denied => 4,
        _ => 2,
    };

    private static void Add(JsonObject json, string name, string? value)
    {
        if (!string.IsNullOrEmpty(value))
            json[name] = value;
    }
}

/// <summary>The event of the "Send test event" button: sent only to that webhook, never published on the event bus.</summary>
/// <param name="WebhookName">The webhook.</param>
public sealed record WebhookTestEvent(string WebhookName) : IEvent
{
    public const string Name = "WebhookTest";

    public EventCategory Category => EventCategory.System;

    public string TypeName => Name;

    public DateTimeOffset Timestamp { get; init; }
}
