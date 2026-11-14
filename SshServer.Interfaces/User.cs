using SshServer.Interfaces.Permissions;

namespace SshServer.Interfaces;



/// <summary>
/// Either provide Password or Key for login
/// </summary>
/// <value></value>
public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string UserRootDirectory { get; set; } = string.Empty;
    public string? HashedPassword { get; set; }
    public string? RsaPublicKey { get; set; }
    public bool OnlyWhitelistedIps { get; set; }
    public List<string>? WhitelistedIps { get; set; }
    public DateTime LastSuccessfulLogin { get; set; }

    /// <summary>
    /// The permissions per virtual directory (issue #59). The longest matching directory wins. Null, or no entry for
    /// "/", means <see cref="FilePermissions.All"/> at the root: a user stored before this property existed keeps
    /// full access. Resolve them with <see cref="IEffectivePermissionsService"/>, never here.
    /// </summary>
    public Dictionary<string, FilePermissions>? Permissions { get; set; } = new() { ["/"] = FilePermissions.All };

    /// <summary>The file name filters per virtual directory (issue #59). Null or empty: no filter.</summary>
    public Dictionary<string, PathFilter>? PathFilters { get; set; }

    /// <summary>
    /// The scope role (issue #60, <see cref="Admins.Role"/>): an administrator with this role as its scope manages the
    /// user. Null: only administrators without a scope see the user.
    /// </summary>
    public int? RoleId { get; set; }
}
