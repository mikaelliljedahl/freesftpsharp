using SshServer.Interfaces.Permissions;

namespace SshServer.Interfaces.Authentication;

/// <summary>
/// The user definition that an external <see cref="IAuthenticationProvider"/> returns with a successful login (issue
/// #64). The user is created with it at the first login ("just in time") and updated with it at the next ones. A null
/// value leaves the stored value as it is. The status, the expiry and the credential are never set from here: the
/// administrator disables a user locally, and the provider checks the credential.
/// <para>
/// Storage and permissions come best from the groups (#61): a group is a template (storage with
/// <c>%username%</c>, virtual folders, permissions), and the provider maps its own groups to local groups.
/// </para>
/// </summary>
public sealed class ExternalUser
{
    /// <summary>The name of the local primary group (compared without case). An unknown name is skipped with a warning.</summary>
    public string? PrimaryGroup { get; init; }

    /// <summary>The names of the local secondary groups, in order. Null: unchanged; empty: none.</summary>
    public IReadOnlyList<string>? Groups { get; init; }

    /// <summary>The user's own permissions per virtual directory (<see cref="User.Permissions"/>). Null: unchanged.</summary>
    public IReadOnlyDictionary<string, FilePermissions>? Permissions { get; init; }

    /// <summary>The networks the user may log in from (CIDR or single addresses). Null: unchanged; empty: every address.</summary>
    public IReadOnlyList<string>? AllowedIps { get; init; }

    /// <summary>
    /// Whether only <see cref="AllowedIps"/> may log in (<see cref="User.OnlyWhitelistedIps"/>). Null: true when
    /// <see cref="AllowedIps"/> is given and not empty, else unchanged.
    /// </summary>
    public bool? OnlyAllowedIps { get; init; }

    /// <summary>The number of sessions at the same time (<see cref="User.MaxSessions"/>, 0: no limit). Null: unchanged.</summary>
    public int? MaxSessions { get; init; }

    /// <summary>The protocols the user may log in with (<see cref="User.AllowedProtocols"/>). Null: unchanged.</summary>
    public UserProtocols? AllowedProtocols { get; init; }

    /// <summary>The note of the user (<see cref="User.Description"/>). Null: unchanged.</summary>
    public string? Description { get; init; }
}
