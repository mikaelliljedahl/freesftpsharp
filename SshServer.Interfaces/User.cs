using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;

namespace SshServer.Interfaces;



/// <summary>
/// Either provide Password or Key for login
/// </summary>
/// <value></value>
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
    public string? RsaPublicKey { get; set; }
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
}
