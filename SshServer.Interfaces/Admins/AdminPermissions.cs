namespace SshServer.Interfaces.Admins;

/// <summary>
/// What an administrator of the admin UI (and later the REST API, #67) may do. The admin UI maps each flag to an
/// ASP.NET Core authorization policy. <see cref="SuperAdmin"/> includes every other flag.
/// </summary>
[Flags]
public enum AdminPermissions
{
    None = 0,

    /// <summary>Everything, also the other administrators. Never together with a scope role.</summary>
    SuperAdmin = 1 << 0,

    /// <summary>Add, change and remove SFTP users (in the scope of the administrator).</summary>
    ManageUsers = 1 << 1,

    /// <summary>Groups (#61).</summary>
    ManageGroups = 1 << 2,

    /// <summary>Virtual folders.</summary>
    ManageFolders = 1 << 3,

    /// <summary>Event rules and webhooks (#66, #68).</summary>
    ManageEvents = 1 << 4,

    /// <summary>See the open connections (of the users in the scope).</summary>
    ViewConnections = 1 << 5,

    /// <summary>Close a connection (of a user in the scope).</summary>
    DisconnectConnections = 1 << 6,

    /// <summary>Read the audit log (the entries of the users in the scope).</summary>
    ViewAudit = 1 << 7,

    /// <summary>The server settings, the IP access lists and the bans.</summary>
    ManageSettings = 1 << 8,

    /// <summary>Administrators and scope roles. An administrator never grants more than it has itself.</summary>
    ManageAdmins = 1 << 9,
}

/// <summary>The rules that turn the stored permissions of an <see cref="Admin"/> into what it may do now.</summary>
public static class AdminPermissionRules
{
    /// <summary>Every flag except <see cref="AdminPermissions.SuperAdmin"/>.</summary>
    public const AdminPermissions AllSingle =
        AdminPermissions.ManageUsers | AdminPermissions.ManageGroups | AdminPermissions.ManageFolders
        | AdminPermissions.ManageEvents | AdminPermissions.ViewConnections | AdminPermissions.DisconnectConnections
        | AdminPermissions.ViewAudit | AdminPermissions.ManageSettings | AdminPermissions.ManageAdmins;

    /// <summary>What a super admin has.</summary>
    public const AdminPermissions Everything = AdminPermissions.SuperAdmin | AllSingle;

    /// <summary>
    /// The flags an administrator with a scope role can have: the ones that work on users, groups and folders of its
    /// role. Server settings, events and administrators are global, so a scoped administrator never gets them.
    /// </summary>
    public const AdminPermissions Scopable =
        AdminPermissions.ManageUsers | AdminPermissions.ManageGroups | AdminPermissions.ManageFolders
        | AdminPermissions.ViewConnections | AdminPermissions.DisconnectConnections | AdminPermissions.ViewAudit;

    /// <summary>
    /// What the administrator may do now: nothing when it is disabled or must change its password first; only the
    /// <see cref="Scopable"/> flags with a scope role; everything as a super admin.
    /// </summary>
    public static AdminPermissions Effective(Admin admin)
    {
        ArgumentNullException.ThrowIfNull(admin);
        if (admin.Status != AdminStatus.Enabled || admin.MustChangePassword)
            return AdminPermissions.None;
        return Effective(admin.Permissions, admin.ScopeRoleId);
    }

    public static AdminPermissions Effective(AdminPermissions granted, int? scopeRoleId)
    {
        if (scopeRoleId != null)
            return granted & Scopable;
        return granted.HasFlag(AdminPermissions.SuperAdmin) ? Everything : granted & AllSingle;
    }

    /// <summary>True when <paramref name="effective"/> has every flag of <paramref name="required"/>.</summary>
    public static bool Has(AdminPermissions effective, AdminPermissions required) =>
        required != AdminPermissions.None && (effective & required) == required;

    /// <summary>The single flags, in the order of the enum, for lists and forms.</summary>
    public static IReadOnlyList<AdminPermissions> SingleFlags { get; } =
        Enum.GetValues<AdminPermissions>().Where(p => p != AdminPermissions.None).ToArray();
}
