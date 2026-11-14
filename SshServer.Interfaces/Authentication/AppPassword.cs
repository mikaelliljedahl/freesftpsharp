using System.Security.Cryptography;
using System.Text;

namespace SshServer.Interfaces.Authentication;

/// <summary>
/// An app password of a user (issue #71): a random secret for one or more protocols, for a client that cannot do the
/// normal login, for example a WebDAV client of a user with a multi-step login. The server makes the secret
/// (<see cref="AppPasswordGenerator"/>) and stores only its SHA-256 hash; the secret is shown once. The secret is random
/// with 160 bits, so a fast hash is enough (as for an API token) and every request can be checked without a key derivation.
/// </summary>
public sealed class AppPassword
{
    /// <summary>A stable id (a GUID in "N" format), for the admin UI and the log; not secret.</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>The name that the administrator gave it, for example "Laptop Finder".</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>"SHA256:" and the base64 of the SHA-256 hash of the secret.</summary>
    public string SecretHash { get; set; } = string.Empty;

    /// <summary>The protocols for which the app password is valid.</summary>
    public UserProtocols Protocols { get; set; } = UserProtocols.WebDav;

    /// <summary>When it was made (UTC).</summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>From this time (UTC) on it is refused. Null: it does not expire.</summary>
    public DateTime? ExpiresAt { get; set; }

    public bool IsExpired(DateTime utcNow) => ExpiresAt is { } expires && expires <= utcNow;

    /// <summary>True when <paramref name="secret"/> is the secret of this app password (compared in constant time).</summary>
    public bool Matches(string? secret)
    {
        if (string.IsNullOrEmpty(secret))
            return false;
        var expected = Encoding.ASCII.GetBytes(SecretHash ?? string.Empty);
        var actual = Encoding.ASCII.GetBytes(AppPasswordGenerator.HashSecret(secret));
        return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);
    }
}

/// <summary>Makes app passwords and checks them against a user.</summary>
public static class AppPasswordGenerator
{
    public const string HashPrefix = "SHA256:";
    public const int MaximumNameLength = 100;

    private const string Alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    /// <summary>
    /// A new app password with a random secret of 28 characters (about 160 bits) in four groups, for example
    /// "abcd-efgh-...". Returns the entry to store and the secret to show once.
    /// </summary>
    public static (AppPassword Entry, string Secret) Create(string name, UserProtocols protocols, DateTime utcNow, DateTime? expiresAtUtc)
    {
        var chars = new char[28];
        for (var i = 0; i < chars.Length; i++)
            chars[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        var secret = string.Join('-', Enumerable.Range(0, 4).Select(g => new string(chars, g * 7, 7)));
        var entry = new AppPassword
        {
            Id = Guid.NewGuid().ToString("N"),
            Name = name.Trim(),
            SecretHash = HashSecret(secret),
            Protocols = protocols,
            CreatedAt = utcNow,
            ExpiresAt = expiresAtUtc,
        };
        return (entry, secret);
    }

    /// <summary>The stored form of a secret.</summary>
    public static string HashSecret(string secret) => HashPrefix + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

    /// <summary>
    /// The app password of <paramref name="user"/> that <paramref name="secret"/> is, when it is valid for
    /// <paramref name="protocol"/> and not expired; otherwise null. Every entry is compared, so the time does not tell
    /// which one matched.
    /// </summary>
    public static AppPassword? Find(User user, string? secret, UserProtocols protocol, DateTime utcNow)
    {
        AppPassword? match = null;
        foreach (var entry in user?.AppPasswords ?? [])
        {
            if (entry != null && entry.Matches(secret) && entry.Protocols.Allows(protocol) && !entry.IsExpired(utcNow))
                match = entry;
        }
        return match;
    }
}
