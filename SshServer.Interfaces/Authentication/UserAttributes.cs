using System.Text.Json;
using SshServer.Interfaces.Permissions;

namespace SshServer.Interfaces.Authentication;

/// <summary>
/// The user attributes that an external authentication provider may set (issue #136), in the JSON form of the user of the
/// REST API (<c>/api/v1/users</c>, #67): camelCase, and the same names and types as <c>UserView</c> and <c>UserWrite</c>
/// there. The answer of the HTTP authentication hook is this object. Every value is optional: null leaves the stored value.
/// <para>
/// It has no root directory, no storage and no secret: the storage comes from the groups (#61). The groups are local
/// group names (<see cref="PrimaryGroup"/>, <see cref="Groups"/>), because the provider does not know the local ids; the
/// REST API has the ids (<c>primaryGroupId</c>, <c>secondaryGroupIds</c>). The status and the expiry stay local
/// (see <see cref="ExternalUser"/>).
/// </para>
/// </summary>
public sealed class UserAttributes
{
    /// <summary>The JSON rules of the REST API: camelCase names, compared without case.</summary>
    public static JsonSerializerOptions JsonOptions { get; } = new(JsonSerializerDefaults.Web);

    /// <summary>The name of the user; when given, it must be the name of the login.</summary>
    public string? Username { get; init; }

    /// <summary>The name of the local primary group (compared without case). Empty: no primary group.</summary>
    public string? PrimaryGroup { get; init; }

    /// <summary>The names of the local secondary groups, in order. Empty: none.</summary>
    public List<string>? Groups { get; init; }

    /// <summary>The permissions per virtual directory, for example <c>{"/": ["List","Download"]}</c> (names of <see cref="FilePermissions"/>).</summary>
    public Dictionary<string, List<string>>? Permissions { get; init; }

    /// <summary>
    /// Whether only <see cref="WhitelistedIps"/> may log in. Not given with <see cref="WhitelistedIps"/>: true when the
    /// list is not empty.
    /// </summary>
    public bool? OnlyWhitelistedIps { get; init; }

    /// <summary>The networks the user may log in from (CIDR or single addresses).</summary>
    public List<string>? WhitelistedIps { get; init; }

    /// <summary>The sessions at the same time; 0: no limit.</summary>
    public int? MaxSessions { get; init; }

    /// <summary>A note (at most 1000 characters are kept).</summary>
    public string? Description { get; init; }

    /// <summary>The permissions as names, or null when there are none.</summary>
    public static Dictionary<string, List<string>>? PermissionNames(IReadOnlyDictionary<string, FilePermissions>? permissions) =>
        permissions is { Count: > 0 }
            ? permissions.ToDictionary(p => p.Key, p => FlagNames.Of(p.Value).ToList(), StringComparer.Ordinal)
            : null;

    /// <summary>The definition for the provisioner. Throws <see cref="FormatException"/> for an unknown permission.</summary>
    public ExternalUser ToExternalUser() => new()
    {
        PrimaryGroup = PrimaryGroup,
        Groups = Groups,
        Permissions = ParsePermissions(Permissions),
        OnlyAllowedIps = OnlyWhitelistedIps,
        AllowedIps = WhitelistedIps,
        MaxSessions = MaxSessions,
        Description = Description,
    };

    private static Dictionary<string, FilePermissions>? ParsePermissions(Dictionary<string, List<string>>? permissions)
    {
        if (permissions == null)
            return null;
        var result = new Dictionary<string, FilePermissions>(StringComparer.Ordinal);
        foreach (var (path, names) in permissions)
        {
            if (names == null)
                throw new FormatException($"the permissions of {path} are not a list");
            var unknown = new List<string>();
            var flags = FlagNames.Parse<FilePermissions>(names, unknown);
            if (unknown.Count > 0)
                throw new FormatException($"unknown permission in {path}");
            result[path] = flags;
        }
        return result;
    }
}
