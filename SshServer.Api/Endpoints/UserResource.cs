using System.Text.Json;
using SshServer.Administration;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Authentication;
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
    private readonly CurrentAdmin _current;

    public UserResource(AdminScopedSettingsRepository repository, UserAdministrationService users, VirtualFolderService folders,
        StorageMapper storage, IAdminStore admins, CurrentAdmin current)
    {
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
        user.Storage = buildStorage(errors);
        if (user.Storage == null && string.IsNullOrWhiteSpace(write.Storage?.Provider) && user.UserRootDirectory.Length == 0)
            errors.Add("rootDirectory", "Enter the root directory of the user on the server, or a storage.");

        if (write.Password != null)
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

        user.Permissions = ParsePermissions(write.Permissions, errors);
        var filters = (write.PathFilters ?? [])
            .Select(f => (Path: NormalizedOrRaw(f.Key), Filter: f.Value?.ToFilter() ?? new PathFilter()))
            .Where(f => !f.Filter.IsEmpty)
            .GroupBy(f => f.Path, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().Filter, StringComparer.Ordinal);
        user.PathFilters = filters.Count == 0 ? null : filters;
        errors.AddRange("permissions", PermissionRulesValidator.Validate(user.Permissions, null));
        errors.AddRange("pathFilters", PermissionRulesValidator.Validate(null, user.PathFilters));

        user.VirtualFolders = (write.VirtualFolders ?? [])
            .Select(m => new VirtualFolderMount { VirtualFolderId = m.VirtualFolderId, MountPath = NormalizedOrRaw(m.MountPath) })
            .ToList();
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
            user.HashedPassword = PasswordHasher.Hash(write.Password);
        else if (write.RemovePassword == true)
            user.HashedPassword = null;
    }

    private static Dictionary<string, FilePermissions> ParsePermissions(Dictionary<string, List<string>>? permissions, ValidationErrors errors)
    {
        if (permissions == null)
            return new Dictionary<string, FilePermissions>(StringComparer.Ordinal) { ["/"] = FilePermissions.All };
        var result = new Dictionary<string, FilePermissions>(StringComparer.Ordinal);
        foreach (var (path, names) in permissions)
        {
            var unknown = new List<string>();
            var flags = FlagNames.Parse<FilePermissions>(names, unknown);
            errors.AddRange("permissions", unknown.Select(n => $"'{n}' is not a file permission."));
            if (!result.TryAdd(NormalizedOrRaw(path), flags))
                errors.Add("permissions", $"The path {NormalizedOrRaw(path)} has permissions twice.");
        }
        return result;
    }

    private static List<string> Entries(IEnumerable<string>? entries) =>
        (entries ?? []).Where(e => !string.IsNullOrWhiteSpace(e)).Select(e => e.Trim()).ToList();

    /// <summary>A valid path is stored normalized; an invalid one is kept as given, so the validation tells about it.</summary>
    private static string NormalizedOrRaw(string? path)
    {
        var trimmed = (path ?? "").Trim();
        return trimmed.StartsWith('/') ? VirtualPath.Normalize(trimmed) : trimmed;
    }

    /// <summary>A deep copy, so a refused change never touches the object of an in-memory repository.</summary>
    private static User Copy(User user) => JsonSerializer.Deserialize<User>(JsonSerializer.Serialize(user, CopyOptions), CopyOptions)!;
}

