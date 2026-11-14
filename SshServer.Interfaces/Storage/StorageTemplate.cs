using System.Text.Json;
using System.Text.Json.Nodes;

namespace SshServer.Interfaces.Storage;

/// <summary>
/// The storage template of a group (issue #61): <see cref="UsernamePlaceholder"/> in a text option of a
/// <see cref="StorageConfig"/>, for example the local directory <c>/srv/sftp/%username%</c> or the S3 key prefix
/// <c>home/%username%/</c>, is replaced by the user name, so every member of the group gets its own folder.
/// </summary>
public static class StorageTemplate
{
    public const string UsernamePlaceholder = "%username%";

    /// <summary>True when a text option of <paramref name="config"/> has the placeholder.</summary>
    public static bool HasPlaceholder(StorageConfig config) =>
        config.Options.Contains(UsernamePlaceholder, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The configuration for <paramref name="username"/>: every text option with the placeholder (without case) has the
    /// user name instead. Encrypted secrets are left as they are. Throws <see cref="ArgumentException"/> for a user name
    /// that would leave the folder of the template ("." or ".." or one with a path separator).
    /// </summary>
    public static StorageConfig Apply(StorageConfig config, string username)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (!HasPlaceholder(config))
            return config;
        if (string.IsNullOrEmpty(username) || username is "." or ".." || username.IndexOfAny(['/', '\\', '\0']) >= 0)
            throw new ArgumentException($"The user name '{username}' cannot be used in the storage template {UsernamePlaceholder}.", nameof(username));

        var node = JsonNode.Parse(config.Options) ?? throw new ArgumentException("The storage options are not a JSON object.", nameof(config));
        Replace(node, username);
        return config with { Options = node.ToJsonString() };
    }

    private static void Replace(JsonNode node, string username)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var (key, value) in obj.ToList())
                {
                    if (value is JsonValue text && text.GetValueKind() == JsonValueKind.String)
                        obj[key] = text.GetValue<string>().Replace(UsernamePlaceholder, username, StringComparison.OrdinalIgnoreCase);
                    else if (value != null)
                        Replace(value, username);
                }
                break;
            case JsonArray array:
                for (var i = 0; i < array.Count; i++)
                {
                    if (array[i] is JsonValue text && text.GetValueKind() == JsonValueKind.String)
                        array[i] = text.GetValue<string>().Replace(UsernamePlaceholder, username, StringComparison.OrdinalIgnoreCase);
                    else if (array[i] is { } child)
                        Replace(child, username);
                }
                break;
        }
    }
}
