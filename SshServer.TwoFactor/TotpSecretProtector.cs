using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace SshServer.TwoFactor;

/// <summary>
/// Encrypts the TOTP secrets for the settings database with ASP.NET Core data protection, like the webhook secrets: the
/// hosts keep the keys in <c>DataProtection:KeysPath</c>. Without the keys a stored secret cannot be read; then the
/// code check fails (closed), and an administrator resets the second factor of the subject.
/// </summary>
public sealed class TotpSecretProtector
{
    public const string Purpose = "FreeSftpSharp.TwoFactor.TotpSecret.v1";

    private readonly IDataProtector _protector;

    public TotpSecretProtector(IDataProtectionProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _protector = provider.CreateProtector(Purpose);
    }

    public string Protect(byte[] secret) => Convert.ToBase64String(_protector.Protect(secret));

    /// <summary>The plain secret; null when it cannot be decrypted (other keys, damaged value). Clear it after use.</summary>
    public byte[]? TryUnprotect(string protectedSecret)
    {
        try
        {
            return _protector.Unprotect(Convert.FromBase64String(protectedSecret));
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return null;
        }
    }
}
