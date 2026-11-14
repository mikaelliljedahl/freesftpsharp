using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;

namespace SshServer.Interfaces;

/// <summary>
/// An SFTP user. It logs in with a password (<see cref="HashedPassword"/>), one of its public keys
/// (<see cref="PublicKeys"/>), or both in a fixed order (<see cref="RequireAllOf"/>).
/// </summary>
public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// The directory on the local disk that is "/" for a user without a <see cref="Storage"/> configuration (the
    /// default storage, <see cref="IDefaultUserStorage"/>). Not used when <see cref="Storage"/> is set.
    /// </summary>
    public string UserRootDirectory { get; set; } = string.Empty;
    public string? HashedPassword { get; set; }

    /// <summary>
    /// The public keys of the user (issue #58). A login compares the whole key blob with each entry that is not expired.
    /// Null or empty: no key login. Make entries with <see cref="SshPublicKey"/>.
    /// </summary>
    public List<PublicKeyEntry>? PublicKeys { get; set; }

    /// <summary>
    /// The login methods that the user may use. Default: all. A refused method fails like a wrong credential. A user
    /// with all methods gets the methods of its groups (issue #61).
    /// </summary>
    public AuthMethods AllowedAuthMethods { get; set; } = AuthMethods.All;

    /// <summary>
    /// A multi-step login: every method in this order, for example [PublicKey, Password] (the key first, then the
    /// password). Each method must be in <see cref="AllowedAuthMethods"/>. Null or empty: one allowed method is enough.
    /// </summary>
    public List<AuthMethods>? RequireAllOf { get; set; }

    public bool OnlyWhitelistedIps { get; set; }
    public List<string>? WhitelistedIps { get; set; }

    /// <summary>The time (UTC) of the last successful login, or null before the first one.</summary>
    public DateTime? LastLoginAt { get; set; }

    /// <summary>A note of the administrator. Not used by the server.</summary>
    public string? Description { get; set; }

    /// <summary>Whether the user may log in (issue #61). A disabled user is refused like a wrong password; its files stay.</summary>
    public UserStatus Status { get; set; } = UserStatus.Enabled;

    /// <summary>The time (UTC) from which the user cannot log in any more (issue #61). Null: never.</summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>The number of sessions the user may have open at the same time (issue #61). 0: no limit.</summary>
    public int MaxSessions { get; set; }

    /// <summary>
    /// The time (UTC) the password was set (issue #61), for <see cref="ServerSettings.PasswordMaxAgeDays"/>. Null: not
    /// known; such a password does not expire.
    /// </summary>
    public DateTime? PasswordChangedAt { get; set; }

    /// <summary>The primary group (issue #61, <see cref="Groups.Group"/>): its settings come first after the user's own.</summary>
    public int? PrimaryGroupId { get; set; }

    /// <summary>The other groups, in the order in which their settings apply after the primary group.</summary>
    public List<int> SecondaryGroupIds { get; set; } = new();

    /// <summary>
    /// The permissions per virtual directory (issue #59). The longest matching directory wins. Null or empty: not set,
    /// the permissions of the groups apply, else <see cref="FilePermissions.All"/> at the root. No entry for "/" means
    /// <see cref="FilePermissions.All"/> at the root. Resolve them with <see cref="Users.IEffectiveUserSettingsService"/>, never here.
    /// </summary>
    public Dictionary<string, FilePermissions>? Permissions { get; set; }

    /// <summary>The file name filters per virtual directory (issue #59). Null or empty: not set, the filters of the groups apply.</summary>
    public Dictionary<string, PathFilter>? PathFilters { get; set; }

    /// <summary>
    /// The storage of "/" (issue #56): a provider and its options. Null: the storage template of the groups (issue #61),
    /// else the default storage, the local disk at <see cref="UserRootDirectory"/>, as before this property existed.
    /// </summary>
    public StorageConfig? Storage { get; set; }

    /// <summary>The virtual folders mounted into the file system of the user (issue #56); the groups can add more.</summary>
    public List<VirtualFolderMount> VirtualFolders { get; set; } = new();

    /// <summary>
    /// The disk quota of the own storage of the user (issue #62): "/" without the virtual folders, which have their own
    /// quota (<see cref="VirtualFolderMount.Quota"/>). Null: unlimited. Resolve it with <see cref="IEffectiveQuotaService"/>.
    /// </summary>
    public DiskQuota? DiskQuota { get; set; }

    /// <summary>The transfer quota of the user (issue #62), until an administrator resets the counters. Null: unlimited.</summary>
    public TransferQuota? TransferQuota { get; set; }

    /// <summary>The bandwidth of each session of the user (issue #62). Null: unlimited.</summary>
    public BandwidthLimit? Bandwidth { get; set; }

    /// <summary>
    /// The scope role (issue #60, <see cref="Admins.Role"/>): an administrator with this role as its scope manages the
    /// user. Null: only administrators without a scope see the user.
    /// </summary>
    public int? RoleId { get; set; }

    /// <summary>
    /// The authentication provider that owns the user (issue #64, <see cref="IAuthenticationProvider.Name"/>), for
    /// example "ldap" for a user that an LDAP directory created at its first login. Only that provider checks its
    /// credential. Null: the local database (the stored password and keys).
    /// </summary>
    public string? AuthenticationProvider { get; set; }

    /// <summary>A shallow copy: the lists and dictionaries are shared; replace them, do not change them in the copy.</summary>
    public User ShallowCopy() => (User)MemberwiseClone();
}

/// <summary>The status of a <see cref="User"/> (issue #61).</summary>
public enum UserStatus
{
    Enabled,
    Disabled,
}
