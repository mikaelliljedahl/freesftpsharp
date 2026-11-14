using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;

namespace SshServer.Api.Endpoints;

/// <summary>
/// An SFTP user in the API: its own settings (the groups, #61, give the settings that are not set here). The password hash
/// and the storage secrets are never returned.
/// </summary>
public sealed record UserView(
    string Username,
    string RootDirectory,
    bool HasPassword,
    IReadOnlyList<PublicKeyView> PublicKeys,
    IReadOnlyList<string> AllowedAuthMethods,
    IReadOnlyList<string> RequireAllOf,
    bool OnlyWhitelistedIps,
    IReadOnlyList<string> WhitelistedIps,
    IReadOnlyDictionary<string, IReadOnlyList<string>>? Permissions,
    IReadOnlyDictionary<string, PathFilterModel> PathFilters,
    StorageView? Storage,
    IReadOnlyList<VirtualFolderMountModel> VirtualFolders,
    int? RoleId,
    string? Description,
    UserStatus Status,
    DateTime? ExpiresAt,
    int MaxSessions,
    int? PrimaryGroupId,
    IReadOnlyList<int> SecondaryGroupIds,
    DateTime? LastLoginAt,
    DateTime? PasswordChangedAt)
{
    public static UserView From(User user, StorageMapper storage) => new(
        user.Username,
        user.UserRootDirectory ?? "",
        !string.IsNullOrEmpty(user.HashedPassword),
        (user.PublicKeys ?? []).Select(PublicKeyView.From).ToList(),
        AuthMethodNames.Of(user.AllowedAuthMethods),
        (user.RequireAllOf ?? []).Select(AuthMethodRules.ToSshName).ToList(),
        user.OnlyWhitelistedIps,
        user.WhitelistedIps?.ToList() ?? [],
        UserWrite.PermissionsOf(user),
        (user.PathFilters ?? []).ToDictionary(f => f.Key, f => PathFilterModel.From(f.Value), StringComparer.Ordinal),
        storage.View(user.Storage),
        (user.VirtualFolders ?? []).Select(m => new VirtualFolderMountModel(m.VirtualFolderId, m.MountPath)).ToList(),
        user.RoleId,
        user.Description,
        user.Status,
        user.ExpiresAt,
        user.MaxSessions,
        user.PrimaryGroupId,
        user.SecondaryGroupIds?.ToList() ?? [],
        user.LastLoginAt,
        user.PasswordChangedAt);
}

/// <summary>A public key of a user: the type, the fingerprint and the comment; the key blob is not needed by a client.</summary>
public sealed record PublicKeyView(string Type, string Fingerprint, string? Comment, DateTime AddedAt, DateTime? ExpiresAt, string Source)
{
    public static PublicKeyView From(PublicKeyEntry key) =>
        new(key.KeyType, key.Fingerprint, key.Comment, key.AddedAt, key.ExpiresAt, key.Source.ToString());
}

/// <summary>The file name filters of one directory (#59): glob patterns.</summary>
public sealed record PathFilterModel(IReadOnlyList<string>? AllowedPatterns, IReadOnlyList<string>? DeniedPatterns, IReadOnlyList<string>? HiddenPatterns)
{
    public static PathFilterModel From(PathFilter filter) => new(filter.AllowedPatterns.ToList(), filter.DeniedPatterns.ToList(), filter.HiddenPatterns.ToList());

    public PathFilter ToFilter() => new()
    {
        AllowedPatterns = Clean(AllowedPatterns),
        DeniedPatterns = Clean(DeniedPatterns),
        HiddenPatterns = Clean(HiddenPatterns),
    };

    private static List<string> Clean(IReadOnlyList<string>? patterns) =>
        (patterns ?? []).Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim()).ToList();
}

/// <summary>A virtual folder (#56) mounted for a user at a path.</summary>
public sealed record VirtualFolderMountModel(int VirtualFolderId, string MountPath);

/// <summary>
/// An SFTP user to create (POST) or to save (PUT; a PATCH is merged into the stored user first). A value that is not
/// given gets its default, except the write-only <see cref="Password"/>: without it the stored password stays.
/// </summary>
public sealed record UserWrite
{
    /// <summary>The name of a new user. It cannot change later.</summary>
    public string? Username { get; init; }

    /// <summary>The root directory on the server for the default storage (needed when <see cref="Storage"/> has no provider).</summary>
    public string? RootDirectory { get; init; }

    /// <summary>A new password (write-only). Not given: the stored password stays.</summary>
    public string? Password { get; init; }

    /// <summary>Removes the stored password (for a user that logs in with a key only).</summary>
    public bool? RemovePassword { get; init; }

    /// <summary>Only for a new user: its public keys, as the text of an OpenSSH authorized_keys file. Later use /public-keys.</summary>
    public string? PublicKeys { get; init; }

    /// <summary>password, publickey, keyboard-interactive. Default: all.</summary>
    public List<string>? AllowedAuthMethods { get; init; }

    /// <summary>A multi-step login in this order, for example ["publickey","password"]. Default: one method is enough.</summary>
    public List<string>? RequireAllOf { get; init; }

    public bool? OnlyWhitelistedIps { get; init; }

    /// <summary>Networks in CIDR notation (or single addresses).</summary>
    public List<string>? WhitelistedIps { get; init; }

    /// <summary>
    /// The permissions per virtual directory, for example {"/": ["All"], "/in": ["List","Upload"]}. Not given: not set,
    /// the groups give them, else All at "/".
    /// </summary>
    public Dictionary<string, List<string>>? Permissions { get; init; }

    public Dictionary<string, PathFilterModel>? PathFilters { get; init; }

    /// <summary>
    /// The storage of "/". Not given: the storage template of a group, else the default storage, the local disk at
    /// <see cref="RootDirectory"/>.
    /// </summary>
    public StorageWrite? Storage { get; init; }

    public List<VirtualFolderMountModel>? VirtualFolders { get; init; }

    /// <summary>The scope role (#60). An administrator with a scope role always gives its own role.</summary>
    public int? RoleId { get; init; }

    /// <summary>A note of the administrator (at most 1000 characters).</summary>
    public string? Description { get; init; }

    /// <summary>Enabled (default) or Disabled: a disabled user cannot log in, its open sessions are closed.</summary>
    public UserStatus? Status { get; init; }

    /// <summary>The time (UTC) from which the user cannot log in. Not given: never.</summary>
    public DateTime? ExpiresAt { get; init; }

    /// <summary>The sessions the user may have open at the same time, 0 to 10000. 0 (default): no limit.</summary>
    public int? MaxSessions { get; init; }

    /// <summary>The primary group (#61).</summary>
    public int? PrimaryGroupId { get; init; }

    /// <summary>The other groups, in the order in which their settings apply.</summary>
    public List<int>? SecondaryGroupIds { get; init; }

    /// <summary>The write model of a stored user, for a PATCH (no password, no keys: they keep their stored values).</summary>
    public static UserWrite From(User user, StorageMapper storage) => new()
    {
        Username = user.Username,
        RootDirectory = user.UserRootDirectory,
        AllowedAuthMethods = AuthMethodNames.Of(user.AllowedAuthMethods).ToList(),
        RequireAllOf = (user.RequireAllOf ?? []).Select(AuthMethodRules.ToSshName).ToList(),
        OnlyWhitelistedIps = user.OnlyWhitelistedIps,
        WhitelistedIps = user.WhitelistedIps?.ToList() ?? [],
        Permissions = PermissionsOf(user)?.ToDictionary(p => p.Key, p => p.Value.ToList(), StringComparer.Ordinal),
        PathFilters = (user.PathFilters ?? []).ToDictionary(f => f.Key, f => PathFilterModel.From(f.Value), StringComparer.Ordinal),
        Storage = storage.WriteModel(user.Storage),
        VirtualFolders = (user.VirtualFolders ?? []).Select(m => new VirtualFolderMountModel(m.VirtualFolderId, m.MountPath)).ToList(),
        RoleId = user.RoleId,
        Description = user.Description,
        Status = user.Status,
        ExpiresAt = user.ExpiresAt,
        MaxSessions = user.MaxSessions,
        PrimaryGroupId = user.PrimaryGroupId,
        SecondaryGroupIds = user.SecondaryGroupIds?.ToList() ?? [],
    };

    /// <summary>The own permissions of the user, or null when it sets none (the groups give them, else All at "/").</summary>
    internal static IReadOnlyDictionary<string, IReadOnlyList<string>>? PermissionsOf(User user) =>
        user.Permissions is { Count: > 0 } permissions
            ? permissions.ToDictionary(p => p.Key, p => FlagNames.Of(p.Value), StringComparer.Ordinal)
            : null;
}

/// <summary>Public keys to add to a user: the text of an authorized_keys file, or one PEM public key.</summary>
public sealed record PublicKeysAdd(string Keys, DateTime? ExpiresAt);

/// <summary>The result of adding public keys: added, and skipped because the user has them already.</summary>
public sealed record PublicKeysAdded(int Added, int Skipped);

/// <summary>A key pair to generate for a user: "ed25519" (default) or "rsa".</summary>
public sealed record GenerateKeyRequest(string? Type);

/// <summary>A generated key pair: the private key is returned only here and is not stored on the server.</summary>
public sealed record GeneratedKey(PublicKeyView PublicKey, string PrivateKey, string FileName);
