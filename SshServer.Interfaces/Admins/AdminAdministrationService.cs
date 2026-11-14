using SshServer.Interfaces.Events;
using SshServer.Interfaces.Net;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Users;

namespace SshServer.Interfaces.Admins;

/// <summary>The fields of an administrator that an operator sets (the admin UI form, the command line).</summary>
public sealed record AdminInput(string Username)
{
    public string? Email { get; init; }
    public AdminStatus Status { get; init; } = AdminStatus.Enabled;
    public AdminPermissions Permissions { get; init; }
    public IReadOnlyList<string> AllowedIps { get; init; } = [];
    public int? ScopeRoleId { get; init; }
    public bool MustChangePassword { get; init; }

    public static AdminInput From(Admin admin) => new(admin.Username)
    {
        Email = admin.Email,
        Status = admin.Status,
        Permissions = admin.Permissions,
        AllowedIps = admin.AllowedIps?.ToList() ?? [],
        ScopeRoleId = admin.ScopeRoleId,
        MustChangePassword = admin.MustChangePassword,
    };
}

/// <summary>
/// The one application service for administrators and scope roles. The admin UI and the command line use it, so the
/// rules exist in one place:
/// <list type="bullet">
/// <item>Every operation needs <see cref="AdminPermissions.ManageAdmins"/> (the <see cref="AdminActor.System"/> actor
/// may do everything).</item>
/// <item>An administrator never grants a permission it does not have, and never changes or removes an administrator
/// that has more permissions than itself (so only a super admin manages super admins).</item>
/// <item>Nobody changes its own permissions, status or scope, or removes itself: the last super admin stays.</item>
/// <item>A super admin has no scope; a scoped administrator has only <see cref="AdminPermissionRules.Scopable"/> flags.</item>
/// </list>
/// Every change is published as a <see cref="ProviderEvent"/> with the actor, without the password hash.
/// </summary>
public sealed class AdminAdministrationService
{
    public const int MinimumPasswordLength = UserAdministrationService.MinimumPasswordLength;
    public const int MaximumEmailLength = 256;
    public const int MaximumRoleNameLength = 100;

    private readonly IAdminStore _store;
    private readonly ISettingsRepository _settings;
    private readonly IEventBus? _events;
    private readonly TimeProvider _time;
    private readonly int _hashIterations;

    /// <param name="hashIterations">The PBKDF2 iterations of new password hashes (tests use the minimum).</param>
    public AdminAdministrationService(IAdminStore store, ISettingsRepository settings, IEventBus? events = null,
        TimeProvider? time = null, int hashIterations = PasswordHasher.DefaultIterations)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _events = events;
        _time = time ?? TimeProvider.System;
        _hashIterations = hashIterations;
    }

    public async Task<IReadOnlyList<Admin>> ListAdminsAsync(AdminActor actor, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageAdmins);
        return await _store.ListAdminsAsync(ct);
    }

    public async Task<Admin> CreateAdminAsync(AdminActor actor, AdminInput input, string password, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageAdmins);
        var name = input.Username?.Trim() ?? "";
        Throw(UserAdministrationService.ValidateUserName(name));
        Throw(ValidatePassword(password));
        await ValidateAsync(input, ct);
        DemandGrantable(actor, input.Permissions);

        var admin = new Admin
        {
            Username = name,
            PasswordHash = PasswordHasher.Hash(password, _hashIterations),
        };
        Apply(input, admin);
        if (!await _store.AddAdminAsync(admin, ct))
            throw new AdminAdministrationException($"The administrator '{name}' already exists.");

        await PublishAsync(ProviderAction.Add, actor, admin, []);
        return admin;
    }

    /// <summary>Changes the administrator with the name of <paramref name="input"/>. A null password keeps the old one.</summary>
    public async Task<Admin> UpdateAdminAsync(AdminActor actor, AdminInput input, string? newPassword, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageAdmins);
        var stored = await GetManageableAsync(actor, input.Username, ct);
        if (newPassword != null)
            Throw(ValidatePassword(newPassword));
        await ValidateAsync(input, ct);
        DemandGrantable(actor, input.Permissions);
        if (IsSelf(actor, stored) && (input.Permissions != stored.Permissions || input.Status != stored.Status
                                      || input.ScopeRoleId != stored.ScopeRoleId))
        {
            throw new AdminAccessDeniedException("You cannot change your own permissions, status or scope. Ask another administrator.");
        }

        var before = AdminSnapshot.From(stored);
        Apply(input, stored);
        if (newPassword != null)
            stored.PasswordHash = PasswordHasher.Hash(newPassword, _hashIterations);
        if (!await _store.UpdateAdminAsync(stored, ct))
            throw new AdminAdministrationException($"The administrator '{stored.Username}' does not exist any more.");

        var changed = ChangedFields(before, AdminSnapshot.From(stored));
        if (newPassword != null)
            changed.Add("Password");
        if (changed.Count > 0)
            await PublishAsync(ProviderAction.Update, actor, stored, changed);
        return stored;
    }

    public async Task DeleteAdminAsync(AdminActor actor, string username, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageAdmins);
        var stored = await GetManageableAsync(actor, username, ct);
        if (IsSelf(actor, stored))
            throw new AdminAccessDeniedException("You cannot remove yourself.");
        if (!await _store.RemoveAdminAsync(stored.Id, ct))
            throw new AdminAdministrationException($"The administrator '{stored.Username}' does not exist any more.");
        await PublishAsync(ProviderAction.Delete, actor, stored, []);
    }

    /// <summary>
    /// The signed-in administrator sets a new password. It needs the current one. Clears
    /// <see cref="Admin.MustChangePassword"/>. Returns the saved administrator.
    /// </summary>
    public async Task<Admin> ChangeOwnPasswordAsync(string username, string currentPassword, string newPassword, CancellationToken ct)
    {
        var stored = await _store.GetAdminAsync(username, ct);
        if (stored == null || stored.Status != AdminStatus.Enabled || !PasswordHasher.Verify(currentPassword ?? "", stored.PasswordHash))
            throw new AdminAccessDeniedException("The current password is not correct.");
        Throw(ValidatePassword(newPassword));
        if (PasswordHasher.Verify(newPassword, stored.PasswordHash))
            throw new AdminAdministrationException("The new password must be different from the current one.");

        stored.PasswordHash = PasswordHasher.Hash(newPassword, _hashIterations);
        var mustChangeBefore = stored.MustChangePassword;
        stored.MustChangePassword = false;
        if (!await _store.UpdateAdminAsync(stored, ct))
            throw new AdminAdministrationException("The administrator does not exist any more.");

        await PublishAsync(ProviderAction.Update, new AdminActor(stored.Username, AdminPermissions.None, null), stored,
            mustChangeBefore ? ["Password", nameof(Admin.MustChangePassword)] : ["Password"]);
        return stored;
    }

    /// <summary>
    /// The bootstrap of an installation from before #60: when no administrator is stored, the configured account
    /// becomes the first super admin. Returns false (and changes nothing) when there are administrators already.
    /// </summary>
    public async Task<bool> ImportConfiguredAdminAsync(string username, string passwordHash, CancellationToken ct)
    {
        if (await _store.AnyAdminAsync(ct))
            return false;
        if (string.IsNullOrWhiteSpace(username) || !PasswordHasher.IsWellFormed(passwordHash))
            throw new AdminAdministrationException("The configured admin account needs a user name and a valid password hash.");

        var admin = new Admin
        {
            Username = username.Trim(),
            PasswordHash = passwordHash,
            Permissions = AdminPermissions.SuperAdmin,
        };
        if (!await _store.AddAdminAsync(admin, ct))
            return false;
        await PublishAsync(ProviderAction.Add, AdminActor.System, admin, []);
        return true;
    }

    /// <summary>Saves the time of a successful login. No event: the login itself is an auth event.</summary>
    public async Task RecordLoginAsync(Admin admin, CancellationToken ct)
    {
        var stored = await _store.GetAdminAsync(admin.Username, ct);
        if (stored == null)
            return;
        stored.LastLoginAt = _time.GetUtcNow().UtcDateTime;
        await _store.UpdateAdminAsync(stored, ct);
    }

    public async Task<IReadOnlyList<Role>> ListRolesAsync(AdminActor actor, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageAdmins);
        return await _store.ListRolesAsync(ct);
    }

    public async Task<Role> CreateRoleAsync(AdminActor actor, string name, string? description, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageAdmins);
        var role = new Role { Name = name?.Trim() ?? "", Description = Normalize(description) };
        Throw(ValidateRoleName(role.Name));
        if (!await _store.AddRoleAsync(role, ct))
            throw new AdminAdministrationException($"The role '{role.Name}' already exists.");
        await PublishRoleAsync(ProviderAction.Add, actor, role, []);
        return role;
    }

    public async Task<Role> UpdateRoleAsync(AdminActor actor, Role role, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageAdmins);
        var stored = await _store.GetRoleAsync(role.Id, ct)
                     ?? throw new AdminAdministrationException("The role does not exist any more.");
        var before = RoleSnapshot.From(stored);
        stored.Name = role.Name?.Trim() ?? "";
        stored.Description = Normalize(role.Description);
        Throw(ValidateRoleName(stored.Name));
        if (!await _store.UpdateRoleAsync(stored, ct))
            throw new AdminAdministrationException($"The role '{stored.Name}' already exists.");
        var changed = ChangedFields(before, RoleSnapshot.From(stored));
        if (changed.Count > 0)
            await PublishRoleAsync(ProviderAction.Update, actor, stored, changed);
        return stored;
    }

    /// <summary>Removes a role that no user and no administrator has.</summary>
    public async Task DeleteRoleAsync(AdminActor actor, int roleId, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageAdmins);
        var stored = await _store.GetRoleAsync(roleId, ct)
                     ?? throw new AdminAdministrationException("The role does not exist any more.");
        var users = _settings.GetAllUsers().Count(u => u.RoleId == roleId);
        var admins = (await _store.ListAdminsAsync(ct)).Count(a => a.ScopeRoleId == roleId);
        if (users > 0 || admins > 0)
            throw new AdminAdministrationException(
                $"The role '{stored.Name}' is used by {users} user(s) and {admins} administrator(s). Remove it from them first.");
        if (!await _store.RemoveRoleAsync(roleId, ct))
            throw new AdminAdministrationException("The role does not exist any more.");
        await PublishRoleAsync(ProviderAction.Delete, actor, stored, []);
    }

    /// <summary>Returns an error text, or null when the password is acceptable.</summary>
    public static string? ValidatePassword(string? password) => UserAdministrationService.ValidatePassword(password);

    public static string? ValidateRoleName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return "Enter a role name.";
        if (name.Length > MaximumRoleNameLength)
            return $"The role name can have at most {MaximumRoleNameLength} characters.";
        return null;
    }

    private async Task<Admin> GetManageableAsync(AdminActor actor, string username, CancellationToken ct)
    {
        var stored = await _store.GetAdminAsync(username?.Trim() ?? "", ct)
                     ?? throw new AdminAdministrationException($"The administrator '{username}' does not exist.");
        if (!actor.IsSystem && (stored.Permissions & ~actor.Permissions) != AdminPermissions.None)
            throw new AdminAccessDeniedException($"The administrator '{stored.Username}' has permissions that you do not have.");
        return stored;
    }

    private async Task ValidateAsync(AdminInput input, CancellationToken ct)
    {
        if (input.ScopeRoleId is { } roleId)
        {
            if (input.Permissions.HasFlag(AdminPermissions.SuperAdmin))
                throw new AdminAdministrationException("A super admin cannot have a scope role.");
            if ((input.Permissions & ~AdminPermissionRules.Scopable) != AdminPermissions.None)
                throw new AdminAdministrationException(
                    $"An administrator with a scope role can only have these permissions: {AdminPermissionRules.Scopable}.");
            if (await _store.GetRoleAsync(roleId, ct) == null)
                throw new AdminAdministrationException("The scope role does not exist.");
        }

        var invalid = CidrNotation.FindInvalid(input.AllowedIps);
        if (invalid.Count > 0)
            throw new AdminAdministrationException($"Not a valid network: {string.Join(", ", invalid)}.");

        var email = Normalize(input.Email);
        if (email != null && (email.Length > MaximumEmailLength || !email.Contains('@') || email.Any(char.IsWhiteSpace)))
            throw new AdminAdministrationException("The e-mail address is not valid.");
    }

    private static void DemandGrantable(AdminActor actor, AdminPermissions requested)
    {
        if (actor.IsSystem)
            return;
        var missing = requested & ~actor.Permissions;
        if (missing != AdminPermissions.None)
            throw new AdminAccessDeniedException($"You cannot grant permissions that you do not have: {missing}.");
    }

    private static bool IsSelf(AdminActor actor, Admin admin) =>
        string.Equals(actor.Username, admin.Username, StringComparison.OrdinalIgnoreCase);

    private static void Apply(AdminInput input, Admin admin)
    {
        admin.Email = Normalize(input.Email);
        admin.Status = input.Status;
        admin.Permissions = input.Permissions;
        admin.AllowedIps = input.AllowedIps.Where(e => !string.IsNullOrWhiteSpace(e)).Select(e => e.Trim()).ToList();
        admin.ScopeRoleId = input.ScopeRoleId;
        admin.MustChangePassword = input.MustChangePassword;
    }

    private static string? Normalize(string? text) => string.IsNullOrWhiteSpace(text) ? null : text.Trim();

    private static void Throw(string? error)
    {
        if (error != null)
            throw new AdminAdministrationException(error);
    }

    private static List<string> ChangedFields<T>(T before, T after)
    {
        var changed = new List<string>();
        foreach (var property in typeof(T).GetProperties())
        {
            var a = property.GetValue(before);
            var b = property.GetValue(after);
            var same = a is IEnumerable<string> listA && b is IEnumerable<string> listB ? listA.SequenceEqual(listB) : Equals(a, b);
            if (!same)
                changed.Add(property.Name);
        }
        return changed;
    }

    private Task PublishAsync(ProviderAction action, AdminActor actor, Admin admin, IReadOnlyList<string> changed) =>
        PublishEventAsync(new ProviderEvent(action, ProviderObjectType.Admin, admin.Username)
        {
            Actor = actor.Username,
            Object = AdminSnapshot.From(admin),
            ChangedFields = changed,
        });

    private Task PublishRoleAsync(ProviderAction action, AdminActor actor, Role role, IReadOnlyList<string> changed) =>
        PublishEventAsync(new ProviderEvent(action, ProviderObjectType.Role, role.Name)
        {
            Actor = actor.Username,
            Object = RoleSnapshot.From(role),
            ChangedFields = changed,
        });

    // The change is saved before; the event is delivered even when the caller gives up waiting.
    private async Task PublishEventAsync(ProviderEvent @event)
    {
        if (_events != null)
            await _events.PublishAsync(@event with { Timestamp = _time.GetUtcNow() }, CancellationToken.None);
    }
}
