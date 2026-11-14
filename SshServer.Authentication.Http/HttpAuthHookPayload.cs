using System.Text.Json;
using System.Text.Json.Nodes;
using SshServer.Interfaces.Authentication;

namespace SshServer.Authentication.Http;

/// <summary>
/// The JSON of the HTTP authentication hook (issue #64).
/// <para>Request (snake_case, unchanged): <c>{"username", "password" (password logins), "public_key" (an authorized_keys
/// line, key logins), "method" ("password", "publickey", "keyboard-interactive"), "ip", "protocol"}</c>.</para>
/// <para>Answer 200: a <see cref="UserAttributes"/> (#136), the names and types of the user of the REST API, every field
/// optional: <c>{"username" (must be the name of the request), "primaryGroup", "groups", "permissions"
/// ({"/": ["List", "Download"]}), "onlyWhitelistedIps", "whitelistedIps", "maxSessions", "allowedProtocols" (["sftp", "webdav"]), "description"}</c>.</para>
/// <para>Deprecated: the snake_case answer of the first version (<c>primary_group</c>, <c>allowed_ips</c>,
/// <c>max_sessions</c>) is still read for one release; <see cref="ParseUser"/> tells when an answer used it.</para>
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

    /// <summary>The snake_case names of the deprecated answer, and their names in <see cref="UserAttributes"/>.</summary>
    internal static readonly IReadOnlyList<(string Legacy, string Current)> LegacyNames =
        [("primary_group", "primaryGroup"), ("allowed_ips", "whitelistedIps"), ("max_sessions", "maxSessions")];

    /// <summary>
    /// Reads the answer of a 200. Throws <see cref="FormatException"/> when it is not a valid user for
    /// <paramref name="username"/>. <paramref name="legacyFormat"/> is true when the answer has a snake_case name of the
    /// deprecated format.
    /// </summary>
    public static ExternalUser ParseUser(string? body, string username, out bool legacyFormat)
    {
        legacyFormat = false;
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
        if (node is not JsonObject json)
            throw new FormatException("the answer is not a JSON object");

        foreach (var (legacy, current) in LegacyNames)
        {
            if (!json.ContainsKey(legacy))
                continue;
            if (json.Any(p => string.Equals(p.Key, current, StringComparison.OrdinalIgnoreCase)))
                throw new FormatException($"the answer has both \"{legacy}\" and \"{current}\"");
            legacyFormat = true;
            var value = json[legacy];
            json.Remove(legacy);
            json[current] = value;
        }

        UserAttributes? user;
        try
        {
            user = json.Deserialize<UserAttributes>(UserAttributes.JsonOptions);
        }
        catch (JsonException ex)
        {
            var name = ex.Path?.TrimStart('$', '.').Split('.', '[')[0];
            if (legacyFormat && LegacyNames.FirstOrDefault(n => string.Equals(n.Current, name, StringComparison.OrdinalIgnoreCase)).Legacy is { } legacyName)
                name = legacyName;
            throw new FormatException(string.IsNullOrEmpty(name) ? "a value has the wrong type" : $"\"{name}\" has the wrong type");
        }
        if (user == null)
            return new ExternalUser();

        if (user.Username != null && !string.Equals(user.Username, username, StringComparison.OrdinalIgnoreCase))
            throw new FormatException("the answer is for another user");
        return user.ToExternalUser();
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
}
