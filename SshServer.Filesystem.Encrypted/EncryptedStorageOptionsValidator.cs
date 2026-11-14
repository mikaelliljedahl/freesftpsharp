using Microsoft.Extensions.Options;

namespace SshServer.Filesystem.Encrypted;

/// <summary>
/// Validates the keys at start when the encrypted storage is enabled: a missing active key, a key of the wrong length,
/// bad base64 or an open key file stop the start with a clear message. A disabled storage needs nothing.
/// </summary>
public sealed class EncryptedStorageOptionsValidator : IValidateOptions<EncryptedStorageOptions>
{
    public ValidateOptionsResult Validate(string? name, EncryptedStorageOptions options)
    {
        if (!options.Enabled)
            return ValidateOptionsResult.Success;
        var problems = MasterKeyLoader.Load(options).Problems;
        return problems.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(problems.Select(p => $"Encrypted storage ({EncryptedStorageOptions.SectionName}:Enabled is true): {p}"));
    }
}
