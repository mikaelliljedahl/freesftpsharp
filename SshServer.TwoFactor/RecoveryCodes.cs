using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SshServer.Interfaces.Security;

namespace SshServer.TwoFactor;

/// <summary>
/// The single-use recovery codes of a second factor: ten random codes like <c>k7m2p-x9qr4</c> (50 bits each), shown once
/// and stored as PBKDF2-SHA256 hashes in the format of <see cref="PasswordHasher"/>. The codes of one enrolment share a
/// salt, so a check derives the key once and compares it with every hash in fixed time.
/// </summary>
public static class RecoveryCodes
{
    public const int Count = 10;
    public const int Length = 10;

    /// <summary>No 0/o, 1/l/i: easy to copy from paper.</summary>
    private const string Alphabet = "23456789abcdefghjkmnpqrstuvwxyz";

    /// <summary>The codes have enough entropy; the minimum iterations keep a check fast.</summary>
    internal const int Iterations = PasswordHasher.MinimumIterations;

    private const int SaltSize = 16;
    private const int KeySize = 32;

    public static IReadOnlyList<string> Generate()
    {
        var codes = new string[Count];
        for (var i = 0; i < codes.Length; i++)
        {
            var text = RandomNumberGenerator.GetString(Alphabet, Length);
            codes[i] = text[..(Length / 2)] + "-" + text[(Length / 2)..];
        }
        return codes;
    }

    /// <summary>The hashes of the codes, with one new salt.</summary>
    public static IReadOnlyList<string> Hash(IReadOnlyList<string> codes)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        return codes.Select(code =>
        {
            var normalized = Normalize(code) ?? throw new ArgumentException("Not a recovery code.", nameof(codes));
            return Format(salt, Derive(normalized, salt));
        }).ToList();
    }

    /// <summary>The code without dashes and spaces, in lower case; null when it is not a recovery code.</summary>
    public static string? Normalize(string? code)
    {
        if (code == null)
            return null;
        var text = code.Replace("-", "", StringComparison.Ordinal).Replace(" ", "", StringComparison.Ordinal).Trim().ToLowerInvariant();
        return text.Length == Length && text.All(c => Alphabet.Contains(c)) ? text : null;
    }

    /// <summary>The index of the hash that <paramref name="code"/> matches, or -1. Every hash is compared.</summary>
    public static int FindMatch(string? code, IReadOnlyList<string> hashes)
    {
        var normalized = Normalize(code);
        if (normalized == null || hashes.Count == 0)
            return -1;

        var match = -1;
        byte[]? salt = null;
        byte[]? key = null;
        for (var i = 0; i < hashes.Count; i++)
        {
            if (!TryParse(hashes[i], out var hashSalt, out var expected))
                continue;
            if (salt == null || !salt.AsSpan().SequenceEqual(hashSalt))
            {
                salt = hashSalt;
                key = Derive(normalized, salt);
            }
            if (CryptographicOperations.FixedTimeEquals(key, expected) && match < 0)
                match = i;
        }
        return match;
    }

    private static byte[] Derive(string normalized, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(normalized), salt, Iterations, HashAlgorithmName.SHA256, KeySize);

    private static string Format(byte[] salt, byte[] key) =>
        string.Join('.', PasswordHasher.Algorithm, Iterations.ToString(CultureInfo.InvariantCulture),
            Convert.ToBase64String(salt), Convert.ToBase64String(key));

    private static bool TryParse(string hash, out byte[] salt, out byte[] key)
    {
        salt = [];
        key = [];
        var parts = hash.Split('.');
        if (parts.Length != 4 || parts[0] != PasswordHasher.Algorithm
            || parts[1] != Iterations.ToString(CultureInfo.InvariantCulture))
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
        return key.Length == KeySize;
    }
}
