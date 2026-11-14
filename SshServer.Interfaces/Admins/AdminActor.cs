namespace SshServer.Interfaces.Admins;

/// <summary>
/// Who does an administrative operation: the signed-in administrator with its effective permissions and scope, or
/// <see cref="System"/> for the command line and the bootstrap. Every check of the admin services uses it.
/// </summary>
/// <param name="Username">The name for the audit log (<c>ProviderEvent.Actor</c>).</param>
/// <param name="Permissions">The effective permissions (<see cref="AdminPermissionRules.Effective(Admin)"/>).</param>
/// <param name="ScopeRoleId">The scope role; null: no scope.</param>
public sealed record AdminActor(string Username, AdminPermissions Permissions, int? ScopeRoleId)
{
    /// <summary>The server itself: the command line (<c>--create-admin</c>) and the import of <c>AdminAuth</c>.</summary>
    public static AdminActor System { get; } = new("system", AdminPermissionRules.Everything, null);

    /// <summary>No login, or a login that is not valid any more: may do nothing.</summary>
    public static AdminActor Anonymous { get; } = new("", AdminPermissions.None, null);

    /// <summary>The name of the REST API key (#67) of this login, or null for a login with a password.</summary>
    public string? ApiKeyName { get; init; }

    /// <summary>The actor in the audit log (<c>ProviderEvent.Actor</c>): the name, and the API key when it used one.</summary>
    public string AuditName => ApiKeyName == null ? Username : $"{Username} (API key {ApiKeyName})";

    public bool IsSystem => ReferenceEquals(this, System);

    public bool IsSuperAdmin => Permissions.HasFlag(AdminPermissions.SuperAdmin);

    public bool Has(AdminPermissions required) => AdminPermissionRules.Has(Permissions, required);

    /// <summary>Throws <see cref="AdminAccessDeniedException"/> when a flag of <paramref name="required"/> is missing.</summary>
    public void Demand(AdminPermissions required)
    {
        if (!Has(required))
            throw new AdminAccessDeniedException($"This needs the permission {required}.");
    }

    /// <summary>True when the user is in the scope: every user without a scope, else only the users of the role.</summary>
    public bool CanSee(User? user) => user != null && (ScopeRoleId == null || user.RoleId == ScopeRoleId);

    public static AdminActor From(Admin admin) =>
        new(admin.Username, AdminPermissionRules.Effective(admin), admin.ScopeRoleId);
}

/// <summary>The administrator may not do the operation. The message is meant for the administrator.</summary>
public sealed class AdminAccessDeniedException : UnauthorizedAccessException
{
    public AdminAccessDeniedException(string message) : base(message)
    {
    }
}

/// <summary>Invalid input for an administrator or role operation. The message is meant for the administrator.</summary>
public sealed class AdminAdministrationException : Exception
{
    public AdminAdministrationException(string message) : base(message)
    {
    }
}
