using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace SshServer.Webhooks;

/// <summary>
/// Encrypts the secret of a webhook for the settings database with ASP.NET Core data protection. The hosts keep the
/// keys in the directory <c>DataProtection:KeysPath</c> (default <c>keys</c> next to the app); without the keys a stored
/// secret cannot be read, and the webhook fails until an admin sets a new secret.
/// </summary>
public sealed class WebhookSecretProtector
{
    public const string Purpose = "FreeSftpSharp.Webhooks.Secret.v1";

    private readonly IDataProtector _protector;

    public WebhookSecretProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector(Purpose);
    }

    public string Protect(string secret) => _protector.Protect(secret);

    /// <summary>The plain secret; null when it cannot be decrypted (other keys, damaged value).</summary>
    public string? TryUnprotect(string protectedSecret)
    {
        try
        {
            return _protector.Unprotect(protectedSecret);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>A new random secret: 32 bytes as 64 hex characters.</summary>
    public static string GenerateSecret() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
}
