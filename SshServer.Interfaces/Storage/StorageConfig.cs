namespace SshServer.Interfaces.Storage;

/// <summary>
/// A stored storage configuration (issue #56): the name of a storage provider (<see cref="IStorageProvider.Name"/>) and
/// its options as JSON text. The core never reads the options itself: it deserializes them into the
/// <see cref="IStorageProvider.OptionsType"/> of the provider, and the provider validates them. Properties marked with
/// <see cref="Security.SecretAttribute"/> are encrypted in <see cref="Options"/> (ASP.NET Core data protection), so a
/// database dump has no secret in clear text.
/// </summary>
public sealed record StorageConfig
{
    /// <summary>The <see cref="IStorageProvider.Name"/>, for example "local" or "s3".</summary>
    public string Provider { get; init; } = string.Empty;

    /// <summary>The options of the provider as a JSON object, with the secrets encrypted.</summary>
    public string Options { get; init; } = "{}";
}
