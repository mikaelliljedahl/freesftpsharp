namespace SshServer.Interfaces.Admins;

/// <summary>An <see cref="Admin"/> without its password hash, for the provider events.</summary>
public sealed record AdminSnapshot(string Username, string Status, string? Email, string Permissions, int? ScopeRoleId,
    IReadOnlyList<string> AllowedIps, bool MustChangePassword)
{
    public static AdminSnapshot From(Admin admin) => new(admin.Username, admin.Status.ToString(), admin.Email,
        admin.Permissions.ToString(), admin.ScopeRoleId, admin.AllowedIps?.ToList() ?? [], admin.MustChangePassword);
}

/// <summary>A <see cref="Role"/> for the provider events.</summary>
public sealed record RoleSnapshot(string Name, string? Description)
{
    public static RoleSnapshot From(Role role) => new(role.Name, role.Description);
}
