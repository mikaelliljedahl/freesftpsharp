using System.Security.Cryptography;

namespace SshServer.Interfaces.Authentication;

/// <summary>Where a public key of a user came from.</summary>
public enum PublicKeySource
{
    /// <summary>Added by an administrator (admin UI, command line) or migrated from the old single key.</summary>
    Admin,

    /// <summary>Added by the user (later: web client, REST API).</summary>
    SelfService,

    /// <summary>Given by an external authentication provider (#64).</summary>
    External,
}

/// <summary>
/// One public key of a user (issue #58), as one line of an OpenSSH <c>authorized_keys</c> file. Make it with
/// <see cref="SshPublicKey"/>, which checks the key and computes the fingerprint.
/// </summary>
public sealed class PublicKeyEntry
{
    /// <summary>The key type in the key blob: <c>ssh-ed25519</c>, <c>ecdsa-sha2-nistp256</c> (384, 521) or <c>ssh-rsa</c>.</summary>
    public string KeyType { get; set; } = string.Empty;

    /// <summary>The SSH public key blob in base64, as in <c>authorized_keys</c>. A login compares the whole blob.</summary>
    public string KeyBase64 { get; set; } = string.Empty;

    /// <summary>"SHA256:..." as OpenSSH shows it (base64 without padding). For display only; a login never compares it.</summary>
    public string Fingerprint { get; set; } = string.Empty;

    public string? Comment { get; set; }

    /// <summary>When the key was added (UTC).</summary>
    public DateTime AddedAt { get; set; }

    /// <summary>From this time (UTC) on the key is refused. Null: the key does not expire.</summary>
    public DateTime? ExpiresAt { get; set; }

    public PublicKeySource Source { get; set; } = PublicKeySource.Admin;

    public bool IsExpired(DateTime utcNow) => ExpiresAt is { } expires && expires <= utcNow;

    /// <summary>True when <paramref name="keyBlob"/> is this key (the whole blob, compared in constant time).</summary>
    public bool Matches(ReadOnlySpan<byte> keyBlob)
    {
        byte[] stored;
        try
        {
            stored = Convert.FromBase64String(KeyBase64);
        }
        catch (FormatException)
        {
            return false;
        }
        return stored.Length == keyBlob.Length && CryptographicOperations.FixedTimeEquals(stored, keyBlob);
    }
}
