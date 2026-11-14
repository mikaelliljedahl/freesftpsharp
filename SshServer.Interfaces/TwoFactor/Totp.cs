using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;

namespace SshServer.Interfaces.TwoFactor;

/// <summary>The HMAC of a TOTP code (RFC 6238 section 1.2). The server uses <see cref="Sha1"/>, like the authenticator apps.</summary>
public enum TotpAlgorithm
{
    Sha1,
    Sha256,
    Sha512,
}

/// <summary>
/// Time-based one-time passwords (RFC 6238 on HOTP, RFC 4226): HMAC-SHA1, 6 digits, 30 second steps from the Unix
/// epoch, as Google Authenticator, Microsoft Authenticator, Authy and hardware TOTP tokens use them. Pure functions; the
/// replay protection (a code works once) is the caller's job with the returned time step.
/// </summary>
public static class Totp
{
    public const int Digits = 6;
    public const int PeriodSeconds = 30;

    /// <summary>The accepted clock difference: one step before and one after the current step.</summary>
    public const int AllowedSkewSteps = 1;

    /// <summary>The size of a new secret: 160 bits, the HMAC-SHA1 block recommendation of RFC 4226 section 4.</summary>
    public const int SecretSize = 20;

    /// <summary>The time step T of RFC 6238 section 4.2: floor((unix time - T0) / X) with T0 = 0.</summary>
    public static long TimeStep(DateTimeOffset time, int periodSeconds = PeriodSeconds)
    {
        if (periodSeconds < 1)
            throw new ArgumentOutOfRangeException(nameof(periodSeconds));
        return (long)Math.Floor(time.ToUnixTimeSeconds() / (double)periodSeconds);
    }

    /// <summary>The code of one time step (RFC 4226 section 5.3, dynamic truncation), with leading zeros.</summary>
    public static string ComputeCode(ReadOnlySpan<byte> secret, long timeStep, int digits = Digits, TotpAlgorithm algorithm = TotpAlgorithm.Sha1)
    {
        if (digits < 6 || digits > 9)
            throw new ArgumentOutOfRangeException(nameof(digits), digits, "A code has 6 to 9 digits.");
        if (secret.IsEmpty)
            throw new ArgumentException("The secret is empty.", nameof(secret));

        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, timeStep);
        Span<byte> hash = stackalloc byte[64];
        var length = algorithm switch
        {
            TotpAlgorithm.Sha1 => HMACSHA1.HashData(secret, counter, hash),
            TotpAlgorithm.Sha256 => HMACSHA256.HashData(secret, counter, hash),
            TotpAlgorithm.Sha512 => HMACSHA512.HashData(secret, counter, hash),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        };

        var offset = hash[length - 1] & 0x0f;
        var binary = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        var modulo = 1;
        for (var i = 0; i < digits; i++)
            modulo *= 10;
        CryptographicOperations.ZeroMemory(hash);
        return (binary % modulo).ToString(CultureInfo.InvariantCulture).PadLeft(digits, '0');
    }

    /// <summary>
    /// The text of a code as the user typed it without spaces, or null when it is not <see cref="Digits"/> digits.
    /// </summary>
    public static string? Normalize(string? code)
    {
        if (code == null)
            return null;
        var text = code.Replace(" ", "", StringComparison.Ordinal).Replace("-", "", StringComparison.Ordinal).Trim();
        return text.Length == Digits && text.All(char.IsAsciiDigit) ? text : null;
    }

    /// <summary>
    /// The time step whose code is <paramref name="code"/>, within <see cref="AllowedSkewSteps"/> of
    /// <paramref name="now"/>, and after <paramref name="lastUsedStep"/>; null when there is none. Every step of the
    /// window is compared in fixed time. The caller saves the returned step as the new last used step, so the same
    /// code (and every older one) is refused afterwards (RFC 6238 section 5.2).
    /// </summary>
    public static long? FindTimeStep(ReadOnlySpan<byte> secret, string? code, DateTimeOffset now, long lastUsedStep)
    {
        var normalized = Normalize(code);
        if (normalized == null)
            return null;

        Span<byte> given = stackalloc byte[Digits];
        for (var i = 0; i < Digits; i++)
            given[i] = (byte)normalized[i];

        long? match = null;
        var current = TimeStep(now);
        Span<byte> expected = stackalloc byte[Digits];
        for (var step = current - AllowedSkewSteps; step <= current + AllowedSkewSteps; step++)
        {
            var text = ComputeCode(secret, step);
            for (var i = 0; i < Digits; i++)
                expected[i] = (byte)text[i];
            if (CryptographicOperations.FixedTimeEquals(given, expected) && step > lastUsedStep && match == null)
                match = step;
        }
        return match;
    }
}
