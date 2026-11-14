using System.Text.Json;
using System.Text.Json.Serialization;
using SshServer.Interfaces.Events;

namespace SshServer.Interfaces.Audit;

/// <summary>Converts an <see cref="IEvent"/> to an <see cref="AuditEntry"/>.</summary>
public static class AuditEntryMapper
{
    public const string StatusOk = "Ok";
    public const string StatusFailed = "Failed";

    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    public static AuditEntry From(IEvent @event)
    {
        var entry = new AuditEntry
        {
            TimestampUtc = @event.Timestamp.UtcDateTime,
            Category = @event.Category.ToString(),
            Type = @event.TypeName,
            Status = StatusOk,
        };

        switch (@event)
        {
            case FileEvent file:
                entry.Username = file.Username;
                entry.RemoteIp = file.RemoteIp;
                entry.Protocol = file.Protocol;
                entry.SessionId = file.SessionId;
                entry.Path = file.VirtualPath;
                entry.TargetPath = file.VirtualTargetPath;
                entry.Size = file.FileSize;
                entry.ElapsedMilliseconds = file.Elapsed is { } elapsed ? (long)elapsed.TotalMilliseconds : null;
                entry.Status = file.Status.ToString();
                entry.Message = file.Message;
                entry.Details = Serialize(new { file.Provider, file.BackendPath, file.OpenFlags, file.Metadata });
                break;

            case AuthEvent auth:
                entry.Username = auth.Username;
                entry.RemoteIp = auth.RemoteIp;
                entry.Protocol = auth.Protocol;
                entry.SessionId = auth.SessionId;
                entry.Status = auth.Type == AuthEventType.LoginFailed ? StatusFailed : StatusOk;
                entry.Message = auth.Reason;
                entry.Details = Serialize(new { auth.Method });
                break;

            case ProviderEvent provider:
                entry.Actor = provider.Actor;
                entry.Path = $"{provider.ObjectType}/{provider.ObjectName}";
                entry.Username = provider.ObjectType == ProviderObjectType.User ? provider.ObjectName : null;
                entry.Message = provider.ChangedFields.Count > 0 ? "Changed: " + string.Join(", ", provider.ChangedFields) : null;
                entry.Details = Serialize(new { provider.ObjectType, provider.ChangedFields, provider.Object });
                break;

            case SystemEvent system:
                entry.Path = system.Source;
                entry.Message = system.Message;
                break;
        }

        return entry;
    }

    private static string Serialize(object value) => JsonSerializer.Serialize(value, Json);
}
