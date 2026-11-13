using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SshServer.Interfaces.Security;

/// <summary>
/// Salted PBKDF2-SHA256 password hashes, for the SFTP users and for the admin UI password.
/// Format: <c>PBKDF2-SHA256.&lt;iterations&gt;.&lt;base64 salt&gt;.&lt;base64 key&gt;</c>.
/// The '.' separator needs no escaping in JSON, environment variables or shells.
/// </summary>
public static class PasswordHasher
{
    public const string Algorithm = "PBKDF2-SHA256";
    public const int DefaultIterations = 600_000;
    public const int MinimumIterations = 100_000;

    // Upper bound so a broken stored value cannot make every login burn CPU for minutes.
    public const int MaximumIterations = 10_000_000;

    private const int SaltSize = 16;
    private const int KeySize = 32;
    private const int LegacySha256Size = 32;

    public static string Hash(string password, int iterations = DefaultIterations)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (iterations < MinimumIterations || iterations > MaximumIterations)
            throw new ArgumentOutOfRangeException(nameof(iterations), iterations,
                $"Iterations must be between {MinimumIterations} and {MaximumIterations}.");

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var key = Derive(password, salt, iterations);
        return string.Join('.', Algorithm, iterations.ToString(CultureInfo.InvariantCulture),
            Convert.ToBase64String(salt), Convert.ToBase64String(key));
    }

    public static bool IsWellFormed([NotNullWhen(true)] string? encodedHash) => TryParse(encodedHash, out _, out _, out _);

    public static bool Verify(string? password, string? encodedHash)
    {
        if (password is null || !TryParse(encodedHash, out var iterations, out var salt, out var expected))
            return false;

        var actual = Derive(password, salt, iterations);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>
    /// Runs the same key derivation as a real check, so a request for an unknown user name takes as long as
    /// one for a real user. Without a well-formed hash it uses <see cref="DefaultIterations"/>.
    /// </summary>
    public static void BurnEquivalentWork(string? encodedHash = null)
    {
        var iterations = TryParse(encodedHash, out var configured, out _, out _) ? configured : DefaultIterations;
        Derive("dummy", new byte[SaltSize], iterations);
    }

    /// <summary>
    /// True for the old, unsalted format: base64 of SHA-256 over the ASCII bytes of the password (before issue #23).
    /// </summary>
    public static bool IsLegacySha256([NotNullWhen(true)] string? storedHash) => TryDecodeLegacy(storedHash, out _);

    /// <summary>
    /// Checks a password against the old, unsalted SHA-256 format in constant time. Only for the migration of
    /// old hashes; new hashes are made with <see cref="Hash"/>.
    /// </summary>
    public static bool VerifyLegacySha256(string? password, string? storedHash)
    {
        if (password is null || !TryDecodeLegacy(storedHash, out var expected))
            return false;

        var actual = SHA256.HashData(Encoding.ASCII.GetBytes(password));
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static bool TryDecodeLegacy(string? storedHash, out byte[] hash)
    {
        hash = [];
        if (string.IsNullOrWhiteSpace(storedHash) || storedHash.Contains('.'))
            return false;

        try
        {
            hash = Convert.FromBase64String(storedHash.Trim());
        }
        catch (FormatException)
        {
            return false;
        }

        return hash.Length == LegacySha256Size;
    }

    private static byte[] Derive(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, KeySize);

    private static bool TryParse(string? encodedHash, out int iterations, out byte[] salt, out byte[] key)
    {
        iterations = 0;
        salt = [];
        key = [];
        if (string.IsNullOrWhiteSpace(encodedHash))
            return false;

        var parts = encodedHash.Trim().Split('.');
        if (parts.Length != 4 || !string.Equals(parts[0], Algorithm, StringComparison.Ordinal))
            return false;
        if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out iterations)
            || iterations < MinimumIterations || iterations > MaximumIterations)
            return false;

        try
        {
            salt = Convert.FromBase64String(parts[2]);
            key = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        return salt.Length >= SaltSize && key.Length == KeySize;
    }
}
