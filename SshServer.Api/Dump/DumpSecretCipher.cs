using System.Security.Cryptography;
using System.Text;

namespace SshServer.Api.Dump;

/// <summary>
/// Encrypts the secrets of a dump with a passphrase of the caller: AES-256-GCM with a key from PBKDF2-SHA256, so a dump
/// can go to another server (with other data protection keys), and is useless without the passphrase.
/// </summary>
internal sealed class DumpSecretCipher
{
    public const string Kdf = "pbkdf2-sha256";
    public const int Iterations = 600_000;
    public const int MinimumPassphraseLength = 12;
    private const string Prefix = "enc:v1:";
    private const string CheckText = "freesftpsharp-dump";
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly byte[] _key;

    private DumpSecretCipher(byte[] key)
    {
        _key = key;
    }

    /// <summary>A cipher with a new salt, and the header of the dump.</summary>
    public static DumpSecretCipher Create(string passphrase, out DumpSecrets header)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var cipher = new DumpSecretCipher(Derive(passphrase, salt, Iterations));
        header = new DumpSecrets(Kdf, Iterations, Convert.ToBase64String(salt), cipher.Protect(CheckText));
        return cipher;
    }

    /// <summary>The cipher of a dump. Throws <see cref="ApiValidationException"/> when the passphrase is wrong.</summary>
    public static DumpSecretCipher Open(string passphrase, DumpSecrets header)
    {
        if (header.Kdf != Kdf || header.Iterations is < 100_000 or > 10_000_000)
            throw new ApiValidationException("secrets", "The secrets of the dump use an unknown encryption.");
        byte[] salt;
        try
        {
            salt = Convert.FromBase64String(header.Salt);
        }
        catch (FormatException)
        {
            throw new ApiValidationException("secrets", "The salt of the dump is not valid.");
        }
        var cipher = new DumpSecretCipher(Derive(passphrase, salt, header.Iterations));
        if (cipher.TryUnprotect(header.Check) != CheckText)
            throw new ApiValidationException("passphrase", "The passphrase is not the one of the dump.");
        return cipher;
    }

    public static string? ValidatePassphrase(string passphrase) =>
        passphrase.Length < MinimumPassphraseLength ? $"The passphrase must have at least {MinimumPassphraseLength} characters." : null;

    public string Protect(string plaintext)
    {
        var data = Encoding.UTF8.GetBytes(plaintext);
        var output = new byte[NonceSize + TagSize + data.Length];
        var nonce = output.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, data, output.AsSpan(NonceSize + TagSize), output.AsSpan(NonceSize, TagSize));
        return Prefix + Convert.ToBase64String(output);
    }

    /// <summary>The plain text, or throws <see cref="ArgumentException"/> when the value is not a secret of this dump.</summary>
    public string Unprotect(string value) =>
        TryUnprotect(value) ?? throw new ArgumentException("A secret of the dump cannot be decrypted with the passphrase.");

    private string? TryUnprotect(string value)
    {
        if (!value.StartsWith(Prefix, StringComparison.Ordinal))
            return null;
        try
        {
            var input = Convert.FromBase64String(value[Prefix.Length..]);
            if (input.Length < NonceSize + TagSize)
                return null;
            var plaintext = new byte[input.Length - NonceSize - TagSize];
            using var aes = new AesGcm(_key, TagSize);
            aes.Decrypt(input.AsSpan(0, NonceSize), input.AsSpan(NonceSize + TagSize), input.AsSpan(NonceSize, TagSize), plaintext);
            return Encoding.UTF8.GetString(plaintext);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            return null;
        }
    }

    private static byte[] Derive(string passphrase, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(passphrase), salt, iterations, HashAlgorithmName.SHA256, 32);
}
