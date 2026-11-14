using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Permissions;
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

    /// <summary>The login methods that the user may use. Default: all. A refused method fails like a wrong credential.</summary>
    public AuthMethods AllowedAuthMethods { get; set; } = AuthMethods.All;

    /// <summary>
    /// A multi-step login: every method in this order, for example [PublicKey, Password] (the key first, then the
    /// password). Each method must be in <see cref="AllowedAuthMethods"/>. Null or empty: one allowed method is enough.
    /// </summary>
    public List<AuthMethods>? RequireAllOf { get; set; }

    /// <summary>
    /// The protocols that the user may log in with (issue #71). Default: all, so a user stored before this property
    /// existed keeps SFTP. A protocol must also be turned on for the server (WebDAV is off by default).
    /// </summary>
    public UserProtocols AllowedProtocols { get; set; } = UserProtocols.All;

    /// <summary>
    /// The app passwords of the user (issue #71): random secrets for one or more protocols, for clients that cannot do
    /// the normal login (for example WebDAV with a multi-step login). Null or empty: none. Make them with
    /// <see cref="AppPasswordGenerator"/>.
    /// </summary>
    public List<AppPassword>? AppPasswords { get; set; }

    public bool OnlyWhitelistedIps { get; set; }
    public List<string>? WhitelistedIps { get; set; }
    public DateTime LastSuccessfulLogin { get; set; }

    /// <summary>
    /// The permissions per virtual directory (issue #59). The longest matching directory wins. Null, or no entry for
    /// "/", means <see cref="FilePermissions.All"/> at the root: a user stored before this property existed keeps
    /// full access. Resolve them with <see cref="IEffectivePermissionsService"/>, never here.
    /// </summary>
    public Dictionary<string, FilePermissions>? Permissions { get; set; } = new() { ["/"] = FilePermissions.All };

    /// <summary>The file name filters per virtual directory (issue #59). Null or empty: no filter.</summary>
    public Dictionary<string, PathFilter>? PathFilters { get; set; }

    /// <summary>
    /// The storage of "/" (issue #56): a provider and its options. Null: the default storage, the local disk at
    /// <see cref="UserRootDirectory"/>, as before this property existed.
    /// </summary>
    public StorageConfig? Storage { get; set; }

    /// <summary>The virtual folders mounted into the file system of the user (issue #56).</summary>
    public List<VirtualFolderMount> VirtualFolders { get; set; } = new();

    /// <summary>
    /// The scope role (issue #60, <see cref="Admins.Role"/>): an administrator with this role as its scope manages the
    /// user. Null: only administrators without a scope see the user.
    /// </summary>
    public int? RoleId { get; set; }
}
