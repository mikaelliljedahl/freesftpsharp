using SshServer.Interfaces.Permissions;

namespace SshServer.Interfaces.Shares;

/// <summary>What a share link lets an outside party do (#70).</summary>
public enum ShareScope
{
    /// <summary>Download the shared files and folders (a folder also as a zip).</summary>
    Read,

    /// <summary>Upload files into the shared folders (an "inbox"); the content is not listed.</summary>
    Write,

    /// <summary>Both.</summary>
    ReadWrite,
}

/// <summary>
/// A share link of a user (#70): one or more virtual paths of the user that a person without an account can download, or
/// a folder that such a person can upload into. Every access goes through the file system of the owner (permissions,
/// quotas, events), limited to <see cref="Paths"/> and to <see cref="ShareRules.PermissionMask"/> of the scope.
/// </summary>
public sealed class Share
{
    /// <summary>The random id in the link: 160 bits, base64url (<see cref="ShareId"/>).</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>The <see cref="User.Id"/> of the owner. Removing the user removes its shares; a new user with the same name never gets them.</summary>
    public int UserId { get; set; }

    /// <summary>The user name of the owner (for the lists).</summary>
    public string Username { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    /// <summary>The shared virtual paths of the owner (normalized, not the root): files or folders.</summary>
    public List<string> Paths { get; set; } = new();

    public ShareScope Scope { get; set; }

    /// <summary>An upload may replace an existing file (with the Overwrite permission of the owner). Default false.</summary>
    public bool AllowOverwrite { get; set; }

    /// <summary>The PBKDF2 hash of the password (<see cref="Security.PasswordHasher"/>), or null for a share without password.</summary>
    public string? PasswordHash { get; set; }

    /// <summary>The share stops working at this time (UTC). Null: it does not expire.</summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>The downloads or uploads the share allows; 0 is unlimited.</summary>
    public int MaxUses { get; set; }

    /// <summary>The downloads and uploads so far.</summary>
    public int UsedCount { get; set; }

    /// <summary>The client networks (CIDR or single addresses) that may use the share; empty or null: every address.</summary>
    public List<string>? AllowedIps { get; set; }

    public DateTime CreatedAt { get; set; }

    public DateTime? LastUsedAt { get; set; }

    public bool HasPassword => PasswordHash != null;

    public Share Clone() => new()
    {
        Id = Id,
        UserId = UserId,
        Username = Username,
        Name = Name,
        Description = Description,
        Paths = Paths.ToList(),
        Scope = Scope,
        AllowOverwrite = AllowOverwrite,
        PasswordHash = PasswordHash,
        ExpiresAt = ExpiresAt,
        MaxUses = MaxUses,
        UsedCount = UsedCount,
        AllowedIps = AllowedIps?.ToList(),
        CreatedAt = CreatedAt,
        LastUsedAt = LastUsedAt,
    };
}

/// <summary>The rules of a share that do not need the storage.</summary>
public static class ShareRules
{
    public const int MaxPaths = 20;
    public const int MaxNameLength = 100;
    public const int MaxDescriptionLength = 1000;

    /// <summary>True when the share can be used at <paramref name="utcNow"/>: not expired and not used up.</summary>
    public static bool IsUsable(Share share, DateTime utcNow) =>
        (share.ExpiresAt is not { } expires || utcNow < DateTime.SpecifyKind(expires, DateTimeKind.Utc))
        && (share.MaxUses <= 0 || share.UsedCount < share.MaxUses);

    /// <summary>
    /// The permissions that the scope allows at most; the file system of the owner is limited to them
    /// (<see cref="ClientContext.PermissionMask"/>), so the share never does more than the owner may, and never more than its scope.
    /// </summary>
    public static FilePermissions PermissionMask(ShareScope scope, bool allowOverwrite)
    {
        var read = FilePermissions.List | FilePermissions.Download;
        var write = FilePermissions.Upload | (allowOverwrite ? FilePermissions.Overwrite : FilePermissions.None);
        return scope switch
        {
            ShareScope.Read => read,
            ShareScope.Write => write,
            _ => read | write,
        };
    }

    public static bool CanRead(ShareScope scope) => scope is ShareScope.Read or ShareScope.ReadWrite;

    public static bool CanWrite(ShareScope scope) => scope is ShareScope.Write or ShareScope.ReadWrite;
}
