using SshServer.Interfaces.Admins;

namespace SshServer.Interfaces.Api;

/// <summary>
/// A key of the REST API (#67) for automation. It belongs to an administrator and acts with that administrator's
/// permissions and scope, optionally narrowed by <see cref="Scopes"/>. Only the SHA-256 hash of the key is stored; the
/// key itself is shown once, when it is created.
/// </summary>
public sealed class ApiKey
{
    public int Id { get; set; }

    /// <summary>A name for the administrator and the audit log, unique per administrator.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>The first characters of the key, so an administrator can tell its keys apart. Not secret.</summary>
    public string Prefix { get; set; } = string.Empty;

    /// <summary>The SHA-256 hash of the key, lower-case hex.</summary>
    public string KeyHash { get; set; } = string.Empty;

    /// <summary>The <see cref="Admin.Id"/> of the owner. Removing the administrator removes its keys.</summary>
    public int AdminId { get; set; }

    /// <summary>
    /// The permissions the key may use, a subset of those of the owner (null: all of them). The effective permissions are
    /// always the current permissions of the owner masked with this value.
    /// </summary>
    public AdminPermissions? Scopes { get; set; }

    public DateTime CreatedAt { get; set; }

    /// <summary>The key is refused after this time (UTC). Null: it does not expire.</summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>The last request with the key (UTC), updated at most once a minute.</summary>
    public DateTime? LastUsedAt { get; set; }

    public bool IsExpired(DateTime utcNow) => ExpiresAt is { } expires && expires <= utcNow;

    public ApiKey Clone() => new()
    {
        Id = Id,
        Name = Name,
        Prefix = Prefix,
        KeyHash = KeyHash,
        AdminId = AdminId,
        Scopes = Scopes,
        CreatedAt = CreatedAt,
        ExpiresAt = ExpiresAt,
        LastUsedAt = LastUsedAt,
    };
}
