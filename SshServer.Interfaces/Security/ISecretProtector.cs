namespace SshServer.Interfaces.Security;

/// <summary>Encrypts secrets at rest, for example the <see cref="SecretAttribute"/> options of a stored storage configuration.</summary>
public interface ISecretProtector
{
    /// <summary>The encrypted form of <paramref name="plaintext"/>, as text.</summary>
    string Protect(string plaintext);

    /// <summary>The plaintext of a value from <see cref="Protect"/>. Throws <see cref="System.Security.Cryptography.CryptographicException"/> when it cannot be decrypted.</summary>
    string Unprotect(string protectedValue);
}
