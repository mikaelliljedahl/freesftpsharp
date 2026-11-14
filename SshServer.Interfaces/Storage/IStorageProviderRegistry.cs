namespace SshServer.Interfaces.Storage;

/// <summary>
/// The registered storage providers. The core finds a backend only here, by name; nothing else switches on the
/// provider name. A backend project registers its provider with one <c>services.AddXStorage()</c> call.
/// </summary>
public interface IStorageProviderRegistry
{
    /// <summary>Every registered provider.</summary>
    IReadOnlyCollection<IStorageProvider> Providers { get; }

    /// <summary>The provider with this name (compared without case); throws <see cref="KeyNotFoundException"/> when none is registered.</summary>
    IStorageProvider Get(string name);
}
