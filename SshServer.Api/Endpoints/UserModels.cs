using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;

namespace SshServer.Api.Endpoints;

/// <summary>
/// An SFTP user in the API: its own settings (the groups, #61, give the settings that are not set here). The password hash
/// and the storage secrets are never returned. The fields that an authentication provider may set have the names and the
/// types of <see cref="UserAttributes"/> (#136), the answer of the authentication hook.
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
    Dictionary<string, List<string>>? Permissions,
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
    DiskQuota? DiskQuota,
    TransferQuota? TransferQuota,
    BandwidthLimit? Bandwidth,
    DateTime? LastLoginAt,
    DateTime? PasswordChangedAt,
    string? AuthenticationProvider,
    IReadOnlyList<string> AllowedProtocols)
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
        UserAttributes.PermissionNames(user.Permissions),
        (user.PathFilters ?? []).ToDictionary(f => f.Key, f => PathFilterModel.From(f.Value), StringComparer.Ordinal),
        storage.View(user.Storage),
        (user.VirtualFolders ?? []).Select(VirtualFolderMountModel.From).ToList(),
        user.RoleId,
        user.Description,
        user.Status,
        user.ExpiresAt,
        user.MaxSessions,
        user.PrimaryGroupId,
        user.SecondaryGroupIds?.ToList() ?? [],
        user.DiskQuota,
        user.TransferQuota,
        user.Bandwidth,
        user.LastLoginAt,
        user.PasswordChangedAt,
        user.AuthenticationProvider,
        ProtocolNames.Of(user.AllowedProtocols));
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

/// <summary>A virtual folder (#56) mounted for a user or a group at a path, with its disk quota for this mount (#62; null: unlimited).</summary>
public sealed record VirtualFolderMountModel(int VirtualFolderId, string MountPath, DiskQuota? Quota = null)
{
    public static VirtualFolderMountModel From(VirtualFolderMount mount) => new(mount.VirtualFolderId, mount.MountPath, mount.Quota);
}

/// <summary>The quotas and the bandwidth (#62) of a user or a group; null: not set (unlimited, or the values of the groups).</summary>
public sealed record QuotaSettingsModel(DiskQuota? DiskQuota, TransferQuota? TransferQuota, BandwidthLimit? Bandwidth);

/// <summary>The quotas of a user: its own settings, and the effective limits with their usage.</summary>
public sealed record UserQuotasView(QuotaSettingsModel Settings, SshServerModule.Quotas.UserQuotaView Usage);

/// <summary>
/// An SFTP user to create (POST) or to save (PUT; a PATCH is merged into the stored user first). A value that is not
/// given gets its default, except the write-only <see cref="Password"/>: without it the stored password stays. The
/// fields of <see cref="UserAttributes"/> (#136) have the same names and types here.
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

    /// <summary>The disk quota of the own storage (#62). Not given: unlimited, or the quota of the groups.</summary>
    public DiskQuota? DiskQuota { get; init; }

    /// <summary>The transfer quota (#62). Not given: unlimited, or the quota of the groups.</summary>
    public TransferQuota? TransferQuota { get; init; }

    /// <summary>The bandwidth per session (#62). Not given: unlimited, or the bandwidth of the groups.</summary>
    public BandwidthLimit? Bandwidth { get; init; }

    /// <summary>
    /// The protocols the user may use (#71): sftp, webdav, web, ftp. Not given: all of them. At least one is needed. The
    /// app passwords have their own routes (/users/{username}/app-passwords).
    /// </summary>
    public List<string>? AllowedProtocols { get; init; }

    /// <summary>The write model of a stored user, for a PATCH (no password, no keys: they keep their stored values).</summary>
    public static UserWrite From(User user, StorageMapper storage) => new()
    {
        Username = user.Username,
        RootDirectory = user.UserRootDirectory,
        AllowedAuthMethods = AuthMethodNames.Of(user.AllowedAuthMethods).ToList(),
        RequireAllOf = (user.RequireAllOf ?? []).Select(AuthMethodRules.ToSshName).ToList(),
        OnlyWhitelistedIps = user.OnlyWhitelistedIps,
        WhitelistedIps = user.WhitelistedIps?.ToList() ?? [],
        Permissions = UserAttributes.PermissionNames(user.Permissions),
        PathFilters = (user.PathFilters ?? []).ToDictionary(f => f.Key, f => PathFilterModel.From(f.Value), StringComparer.Ordinal),
        Storage = storage.WriteModel(user.Storage),
        VirtualFolders = (user.VirtualFolders ?? []).Select(VirtualFolderMountModel.From).ToList(),
        RoleId = user.RoleId,
        Description = user.Description,
        Status = user.Status,
        ExpiresAt = user.ExpiresAt,
        MaxSessions = user.MaxSessions,
        PrimaryGroupId = user.PrimaryGroupId,
        SecondaryGroupIds = user.SecondaryGroupIds?.ToList() ?? [],
        DiskQuota = user.DiskQuota,
        TransferQuota = user.TransferQuota,
        Bandwidth = user.Bandwidth,
        AllowedProtocols = ProtocolNames.Of(user.AllowedProtocols).ToList(),
    };
}

/// <summary>Public keys to add to a user: the text of an authorized_keys file, or one PEM public key.</summary>
public sealed record PublicKeysAdd(string Keys, DateTime? ExpiresAt);

/// <summary>The result of adding public keys: added, and skipped because the user has them already.</summary>
public sealed record PublicKeysAdded(int Added, int Skipped);

/// <summary>A key pair to generate for a user: "ed25519" (default) or "rsa".</summary>
public sealed record GenerateKeyRequest(string? Type);

/// <summary>A generated key pair: the private key is returned only here and is not stored on the server.</summary>
public sealed record GeneratedKey(PublicKeyView PublicKey, string PrivateKey, string FileName);

/// <summary>An app password (#71) of a user: the metadata only. The secret is shown once, when it is created.</summary>
public sealed record AppPasswordView(string Id, string Name, IReadOnlyList<string> Protocols, DateTime CreatedAt, DateTime? ExpiresAt, bool Expired)
{
    public static AppPasswordView From(AppPassword password, DateTime utcNow) => new(password.Id, password.Name, ProtocolNames.Of(password.Protocols),
        ApiTime.ToUtc(password.CreatedAt), ApiTime.ToUtc(password.ExpiresAt), password.IsExpired(utcNow));
}

/// <summary>An app password to create: a name, the protocols (default: webdav) and an optional expiry (UTC).</summary>
public sealed record AppPasswordCreate(string? Name, List<string>? Protocols, DateTime? ExpiresAt);

/// <summary>A new app password. The <see cref="Secret"/> is returned only here; the server keeps its hash.</summary>
public sealed record AppPasswordCreated(AppPasswordView AppPassword, string Secret);

/// <summary>The second factor (#63) of a user or an administrator: never the secret. State is Off, Pending (set up, not confirmed) or On.</summary>
public sealed record TwoFactorView(bool Enrolled, string State, DateTime? CreatedAt, DateTime? EnabledAt, int RecoveryCodesLeft)
{
    public static TwoFactorView From(SshServer.TwoFactor.TwoFactorStatus status) => new(status.State == SshServer.TwoFactor.TwoFactorState.On,
        status.State.ToString(), ApiTime.ToUtc(status.CreatedAt), ApiTime.ToUtc(status.EnabledAt), status.RecoveryCodesLeft);
}
