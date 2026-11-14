namespace SshServer.Interfaces.Admins;

/// <summary>
/// The store of the administrators and the scope roles, in the settings database. It only stores: the rules (who may
/// change what, validation, events) are in <see cref="AdminAdministrationService"/>. Names are compared without case.
/// The returned objects are copies: change them and call the update methods to save.
/// </summary>
public interface IAdminStore
{
    /// <summary>False when no administrator is stored yet (a new installation or an upgrade).</summary>
    Task<bool> AnyAdminAsync(CancellationToken ct);

    Task<IReadOnlyList<Admin>> ListAdminsAsync(CancellationToken ct);

    /// <summary>The administrator, or null.</summary>
    Task<Admin?> GetAdminAsync(string username, CancellationToken ct);

    /// <summary>Adds a copy and sets <see cref="Admin.Id"/>. False when the name is empty or used.</summary>
    Task<bool> AddAdminAsync(Admin admin, CancellationToken ct);

    /// <summary>Saves the administrator with the same <see cref="Admin.Id"/>. False when there is none.</summary>
    Task<bool> UpdateAdminAsync(Admin admin, CancellationToken ct);

    Task<bool> RemoveAdminAsync(int id, CancellationToken ct);

    Task<IReadOnlyList<Role>> ListRolesAsync(CancellationToken ct);

    Task<Role?> GetRoleAsync(int id, CancellationToken ct);

    /// <summary>Adds a copy and sets <see cref="Role.Id"/>. False when the name is empty or used.</summary>
    Task<bool> AddRoleAsync(Role role, CancellationToken ct);

    /// <summary>Saves the role with the same id. False when there is none or the new name is used.</summary>
    Task<bool> UpdateRoleAsync(Role role, CancellationToken ct);

    /// <summary>Removes the role. The caller checks first that no user or administrator has it.</summary>
    Task<bool> RemoveRoleAsync(int id, CancellationToken ct);
}
