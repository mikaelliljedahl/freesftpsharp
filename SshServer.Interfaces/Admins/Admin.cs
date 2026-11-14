namespace SshServer.Interfaces.Admins;

public enum AdminStatus
{
    Enabled,
    Disabled,
}

/// <summary>
/// An administrator of the admin UI. Separate from the SFTP <see cref="User"/>s. Stored in the settings database
/// (<see cref="IAdminStore"/>). The configured <c>AdminAuth</c> account is imported once as the first super admin.
/// </summary>
public class Admin
{
    public int Id { get; set; }

    public string Username { get; set; } = string.Empty;

    /// <summary>A hash made by <see cref="Security.PasswordHasher.Hash"/>; never a plaintext password.</summary>
    public string PasswordHash { get; set; } = string.Empty;

    public AdminStatus Status { get; set; } = AdminStatus.Enabled;

    public string? Email { get; set; }

    /// <summary>The granted permissions. Use <see cref="AdminPermissionRules.Effective(Admin)"/> to check them.</summary>
    public AdminPermissions Permissions { get; set; }

    /// <summary>The networks (CIDR, like the user whitelist) the administrator may log in from. Empty: any.</summary>
    public List<string>? AllowedIps { get; set; }

    /// <summary>
    /// The scope <see cref="Role"/>: the administrator sees and manages only users (later groups and folders) with this
    /// role. Null: no scope, everything.
    /// </summary>
    public int? ScopeRoleId { get; set; }

    public DateTime? LastLoginAt { get; set; }

    /// <summary>The administrator must set a new password after the next login before it can do anything.</summary>
    public bool MustChangePassword { get; set; }

    /// <summary>
    /// The owner of the password (#145): null for a local administrator (the stored hash), or the name of the identity
    /// provider that created it, for example <c>oidc</c> for an administrator of the OpenID Connect sign-in. Such an
    /// administrator has no usable local password; the admin UI and the REST API refuse to set one
    /// (<see cref="Authentication.ExternalCredentials"/>).
    /// </summary>
    public string? AuthenticationProvider { get; set; }

    public Admin Clone() => new()
    {
        Id = Id,
        Username = Username,
        PasswordHash = PasswordHash,
        Status = Status,
        Email = Email,
        Permissions = Permissions,
        AllowedIps = AllowedIps?.ToList(),
        ScopeRoleId = ScopeRoleId,
        LastLoginAt = LastLoginAt,
        MustChangePassword = MustChangePassword,
        AuthenticationProvider = AuthenticationProvider,
    };
}

/// <summary>
/// A scope role (SFTPGo "roles"): users with the role belong to it, and an administrator with the role as its
/// <see cref="Admin.ScopeRoleId"/> manages only them. It separates tenants inside one server.
/// </summary>
public class Role
{
    public int Id { get; set; }

    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    public Role Clone() => new() { Id = Id, Name = Name, Description = Description };
}
