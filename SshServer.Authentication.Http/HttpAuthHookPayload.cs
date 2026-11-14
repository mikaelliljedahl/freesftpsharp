using System.Text.Json;
using System.Text.Json.Nodes;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Permissions;

namespace SshServer.Authentication.Http;

/// <summary>
/// The JSON of the HTTP authentication hook (issue #64), in snake_case like the external authentication hook of SFTPGo.
/// <para>Request: <c>{"username", "password" (password logins), "public_key" (an authorized_keys line, key logins),
/// "method" ("password", "publickey", "keyboard-interactive"), "ip", "protocol"}</c>.</para>
/// <para>Answer 200: a user, every field optional: <c>{"username" (must be the name of the request), "primary_group",
/// "groups", "permissions" ({"/": ["List", "Download"]}), "allowed_ips", "max_sessions", "description"}</c>.</para>
/// </summary>
public static class HttpAuthHookPayload
{
    public static string CreateRequest(AuthRequest request)
    {
        var json = new JsonObject
        {
            ["username"] = request.Username,
            ["method"] = AuthMethodRules.ToSshName(request.Method),
            ["protocol"] = request.Protocol,
        };
        if (request.RemoteIp != null)
            json["ip"] = request.RemoteIp;
        if (request.Password != null)
            json["password"] = request.Password;
        if (request.PublicKey != null)
            json["public_key"] = AuthorizedKeysLine(request.PublicKey);
        return json.ToJsonString();
    }

    /// <summary>Reads the answer of a 200. Throws <see cref="FormatException"/> when it is not a valid user for <paramref name="username"/>.</summary>
    public static ExternalUser ParseUser(string? body, string username)
    {
        if (string.IsNullOrWhiteSpace(body))
            return new ExternalUser();

        JsonNode? node;
        try
        {
            node = JsonNode.Parse(body);
        }
        catch (JsonException)
        {
            throw new FormatException("the answer is not JSON");
        }
        if (node is not JsonObject user)
            throw new FormatException("the answer is not a JSON object");

        var name = String(user, "username");
        if (name != null && !string.Equals(name, username, StringComparison.OrdinalIgnoreCase))
            throw new FormatException("the answer is for another user");

        return new ExternalUser
        {
            PrimaryGroup = String(user, "primary_group"),
            Groups = Strings(user, "groups"),
            Permissions = Permissions(user),
            AllowedIps = Strings(user, "allowed_ips"),
            MaxSessions = user["max_sessions"] is { } max ? Int(max, "max_sessions") : null,
            Description = String(user, "description"),
        };
    }

    private static string AuthorizedKeysLine(byte[] blob)
    {
        // The blob starts with the key type as an SSH string (RFC 4253 section 6.6).
        var type = "unknown";
        if (blob.Length >= 4)
        {
            var length = (blob[0] << 24) | (blob[1] << 16) | (blob[2] << 8) | blob[3];
            if (length > 0 && length <= blob.Length - 4)
                type = System.Text.Encoding.ASCII.GetString(blob, 4, length);
        }
        return $"{type} {Convert.ToBase64String(blob)}";
    }

    private static string? String(JsonObject json, string name) => json[name] switch
    {
        null => null,
        JsonValue value when value.TryGetValue<string>(out var text) => text,
        _ => throw new FormatException($"\"{name}\" is not a string"),
    };

    private static int Int(JsonNode node, string name) =>
        node is JsonValue value && value.TryGetValue<int>(out var number) ? number : throw new FormatException($"\"{name}\" is not a number");

    private static List<string>? Strings(JsonObject json, string name) => json[name] switch
    {
        null => null,
        JsonArray array => array.Select(item => item is JsonValue v && v.TryGetValue<string>(out var s) ? s : throw new FormatException($"\"{name}\" is not a list of strings")).ToList(),
        _ => throw new FormatException($"\"{name}\" is not a list"),
    };

    private static Dictionary<string, FilePermissions>? Permissions(JsonObject json)
    {
        if (json["permissions"] is null)
            return null;
        if (json["permissions"] is not JsonObject paths)
            throw new FormatException("\"permissions\" is not an object");
        var result = new Dictionary<string, FilePermissions>(StringComparer.Ordinal);
        foreach (var (path, value) in paths)
        {
            if (value is not JsonArray names)
                throw new FormatException($"the permissions of {path} are not a list");
            var flags = FilePermissions.None;
            foreach (var item in names)
            {
                if (item is not JsonValue v || !v.TryGetValue<string>(out var text)
                    || !Enum.TryParse<FilePermissions>(text, ignoreCase: true, out var flag) || int.TryParse(text, out _))
                    throw new FormatException($"unknown permission in {path}");
                flags |= flag;
            }
            result[path] = flags;
        }
        return result;
    }
}
