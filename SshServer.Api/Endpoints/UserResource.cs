using System.Text.Json;
using SshServer.Administration;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Net;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.Users;
using SshServerModule.Storage;

namespace SshServer.Api.Endpoints;

/// <summary>
/// The SFTP users of the API, over the same scoped services as the Users page: <see cref="AdminScopedSettingsRepository"/>
/// (permission <see cref="AdminPermissions.ManageUsers"/> and the scope of the caller), <see cref="UserAdministrationService"/>
/// and <see cref="VirtualFolderService"/>, with the rules of the shared validators.
/// </summary>
public sealed class UserResource
{
    private static readonly JsonSerializerOptions CopyOptions = new();

    private readonly AdminScopedSettingsRepository _repository;
    private readonly UserAdministrationService _users;
    private readonly VirtualFolderService _folders;
    private readonly StorageMapper _storage;
    private readonly IAdminStore _admins;
    private readonly GroupService _groups;
    private readonly CurrentAdmin _current;
    private readonly TimeProvider _time;

    public UserResource(AdminScopedSettingsRepository repository, UserAdministrationService users, VirtualFolderService folders,
        StorageMapper storage, IAdminStore admins, GroupService groups, CurrentAdmin current, TimeProvider time)
    {
        _groups = groups;
        _time = time;
        _repository = repository;
        _users = users;
        _folders = folders;
        _storage = storage;
        _admins = admins;
        _current = current;
    }

    public StorageMapper Storage => _storage;

    public IEnumerable<User> List(string? search, int? roleId)
    {
        _current.Actor.Demand(AdminPermissions.ManageUsers);
        return _repository.GetAllUsers()
            .Where(u => string.IsNullOrWhiteSpace(search) || u.Username.Contains(search.Trim(), StringComparison.OrdinalIgnoreCase))
            .Where(u => roleId == null || u.RoleId == roleId)
            .OrderBy(u => u.Username, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>A copy of the user, or null when it does not exist or is not in the scope.</summary>
    public User? Get(string username)
    {
        _current.Actor.Demand(AdminPermissions.ManageUsers);
        var user = _repository.GetUser(username);
        return user == null ? null : Copy(user);
    }

    public async Task<User> CreateAsync(UserWrite write, CancellationToken ct)
    {
        var user = new User();
        await ApplyAsync(write, user, isNew: true, ct);
        if (!_users.TryAdd(user))
            throw new ApiConflictException($"The user '{user.Username}' already exists.");
        return Get(user.Username) ?? user;
    }

    /// <summary>Saves the user with <paramref name="write"/>; null when it does not exist (or is not in the scope).</summary>
    public async Task<User?> ReplaceAsync(string username, UserWrite write, CancellationToken ct)
    {
        var user = Get(username);
        if (user == null)
            return null;
        await ApplyAsync(write, user, isNew: false, ct);
        return _repository.UpdateUser(user) ? Get(username) : null;
    }

    private Task ApplyAsync(UserWrite write, User user, bool isNew, CancellationToken ct)
    {
        var stored = user.Storage;
        return ApplyAsync(write, user, isNew, errors => _storage.Build(write.Storage, stored, errors, "storage"), ct);
    }

    /// <summary>
    /// Writes <paramref name="write"/> to <paramref name="user"/> after the rules of the Users page, or throws
    /// <see cref="ApiValidationException"/> with every problem. <paramref name="buildStorage"/> gives the storage of "/"
    /// (null: the default storage). The dump load uses it with the storage of the dump.
    /// </summary>
    internal async Task ApplyAsync(UserWrite write, User user, bool isNew, Func<ValidationErrors, StorageConfig?> buildStorage, CancellationToken ct)
    {
        var errors = new ValidationErrors();
        if (isNew)
        {
            user.Username = write.Username?.Trim() ?? "";
            errors.Add("username", UserAdministrationService.ValidateUserName(user.Username));
        }
        else if (write.Username != null && !string.Equals(write.Username.Trim(), user.Username, StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("username", "The user name cannot change.");
        }

        user.UserRootDirectory = write.RootDirectory?.Trim() ?? "";
        user.PrimaryGroupId = write.PrimaryGroupId;
        user.SecondaryGroupIds = (write.SecondaryGroupIds ?? []).ToList();
        // Like the Users page: the groups outside the scope of the caller are not checked (they stay as they are).
        var visible = _groups.List().ToDictionary(g => g.Id);
        errors.AddRange("groups", _groups.ValidateMembership(new User
        {
            PrimaryGroupId = user.PrimaryGroupId is { } primary && visible.ContainsKey(primary) ? primary : null,
            SecondaryGroupIds = user.SecondaryGroupIds.Where(visible.ContainsKey).ToList(),
        }));
        var groupStorage = new[] { user.PrimaryGroupId }.Concat(user.SecondaryGroupIds.Select(id => (int?)id))
            .Any(id => id is { } g && visible.TryGetValue(g, out var group) && group.Storage != null);

        user.Storage = buildStorage(errors);
        if (user.Storage == null && !groupStorage && string.IsNullOrWhiteSpace(write.Storage?.Provider) && user.UserRootDirectory.Length == 0)
            errors.Add("rootDirectory", "Enter the root directory of the user on the server, a storage, or a group with a storage.");

        user.Description = string.IsNullOrWhiteSpace(write.Description) ? null : write.Description.Trim();
        if (user.Description?.Length > 1000)
            errors.Add("description", "The description can have at most 1000 characters.");
        user.Status = write.Status ?? UserStatus.Enabled;
        user.ExpiresAt = ApiTime.ToUtc(write.ExpiresAt);
        user.MaxSessions = write.MaxSessions ?? 0;
        if (user.MaxSessions is < 0 or > 10_000)
            errors.Add("maxSessions", "The session limit must be from 0 to 10000 (0: no limit).");

        if (write.Password != null && ExternalCredentials.PasswordManagedBy(user) is { } provider)
        {
            // The provider checks the password (#64); a stored one would never be used.
            errors.Add("password", ExternalCredentials.PasswordManagedMessage(provider));
        }
        else if (write.Password != null)
        {
            errors.Add("password", UserAdministrationService.ValidatePassword(write.Password));
            if (write.RemovePassword == true)
                errors.Add("removePassword", "Give a new password or remove the password, not both.");
        }

        if (write.PublicKeys != null)
        {
            if (!isNew)
                errors.Add("publicKeys", "Change the keys of a user with /users/{username}/public-keys.");
            else
            {
                try
                {
                    user.PublicKeys = UserAdministrationService.ParsePublicKeys(write.PublicKeys, PublicKeySource.Admin, null).ToList();
                }
                catch (UserAdministrationException ex)
                {
                    errors.Add("publicKeys", ex.Message);
                }
            }
        }

        var unknown = new List<string>();
        user.AllowedAuthMethods = write.AllowedAuthMethods == null ? AuthMethods.All : AuthMethodNames.Parse(write.AllowedAuthMethods, unknown);
        errors.AddRange("allowedAuthMethods", unknown.Select(n => $"'{n}' is not a login method (password, publickey, keyboard-interactive)."));
        unknown.Clear();
        var steps = (write.RequireAllOf ?? []).Select(n => AuthMethodNames.Parse([n], unknown)).ToList();
        errors.AddRange("requireAllOf", unknown.Select(n => $"'{n}' is not a login method (password, publickey)."));
        user.RequireAllOf = steps.Count == 0 ? null : steps;
        errors.AddRange("allowedAuthMethods", AuthMethodRules.Validate(user.AllowedAuthMethods, user.RequireAllOf));

        user.OnlyWhitelistedIps = write.OnlyWhitelistedIps ?? false;
        user.WhitelistedIps = Entries(write.WhitelistedIps);
        errors.AddRange("whitelistedIps", CidrNotation.FindInvalid(user.WhitelistedIps).Select(e => $"'{e}' is not an IP address or a network in CIDR notation."));

        user.Permissions = PermissionModels.Parse(write.Permissions, errors);
        user.PathFilters = PermissionModels.ParseFilters(write.PathFilters);
        errors.AddRange("permissions", PermissionRulesValidator.Validate(user.Permissions, null));
        errors.AddRange("pathFilters", PermissionRulesValidator.Validate(null, user.PathFilters));

        user.VirtualFolders = PermissionModels.Mounts(write.VirtualFolders);
        QuotaModels.Validate(errors, write.DiskQuota, write.TransferQuota, write.Bandwidth, user.VirtualFolders);
        (user.DiskQuota, user.TransferQuota, user.Bandwidth) = QuotaModels.Normalize(write.DiskQuota, write.TransferQuota, write.Bandwidth);
        errors.AddRange("virtualFolders", _folders.ValidateMounts(user.VirtualFolders));

        // An administrator with a scope role cannot choose another role (the scoped repository refuses it or keeps the stored one).
        if (_current.Actor.ScopeRoleId == null)
        {
            user.RoleId = write.RoleId;
            if (write.RoleId is { } roleId && await _admins.GetRoleAsync(roleId, ct) == null)
                errors.Add("roleId", "The role does not exist.");
        }
        else if (isNew)
        {
            user.RoleId = write.RoleId;
        }

        errors.ThrowIfAny();
        if (write.Password != null)
        {
            user.HashedPassword = PasswordHasher.Hash(write.Password);
            user.PasswordChangedAt = _time.GetUtcNow().UtcDateTime;
        }
        else if (write.RemovePassword == true)
        {
            user.HashedPassword = null;
            user.PasswordChangedAt = null;
        }
    }

    private static List<string> Entries(IEnumerable<string>? entries) =>
        (entries ?? []).Where(e => !string.IsNullOrWhiteSpace(e)).Select(e => e.Trim()).ToList();

    /// <summary>A deep copy, so a refused change never touches the object of an in-memory repository.</summary>
    private static User Copy(User user) => JsonSerializer.Deserialize<User>(JsonSerializer.Serialize(user, CopyOptions), CopyOptions)!;
}

