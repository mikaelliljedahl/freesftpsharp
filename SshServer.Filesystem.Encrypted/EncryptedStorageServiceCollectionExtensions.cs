using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.Encrypted;

public static class EncryptedStorageServiceCollectionExtensions
{
    /// <summary>
    /// Registers the encrypted local disk storage provider ("local-encrypted"), the master keys from the configuration
    /// section <c>Storage:Encryption</c> (<see cref="ConfigurationMasterKeyProvider"/>), and the switch
    /// <c>Storage:Encryption:Enabled</c> that gives every user without a storage configuration the encrypted local disk.
    /// An admin can select "local-encrypted" for a single user or virtual folder too; that needs the keys, not the switch. Also registers the plain local
    /// disk (<see cref="LocalDiskStorageServiceCollectionExtensions.AddLocalDiskStorage"/>). Needs
    /// <see cref="IConfiguration"/> in the services (every host has it).
    /// <para>
    /// Nothing changes while <c>Enabled</c> is false. When it is true, the start fails with a clear message if the
    /// active key is missing or not valid.
    /// </para>
    /// </summary>
    public static IServiceCollection AddEncryptedLocalStorage(this IServiceCollection services)
    {
        services.AddLocalDiskStorage();
        services.AddOptions<EncryptedStorageOptions>()
            .Configure<IConfiguration>((options, configuration) => Bind(configuration.GetSection(EncryptedStorageOptions.SectionName), options))
            .ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<EncryptedStorageOptions>, EncryptedStorageOptionsValidator>());
        services.TryAddSingleton<IMasterKeyProvider, ConfigurationMasterKeyProvider>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IStorageProvider, EncryptedLocalStorageProvider>());
        services.Replace(ServiceDescriptor.Singleton<IDefaultUserStorage, EncryptedUserRootDefaultStorage>());
        return services;
    }

    /// <summary>Binds the section by hand: the configuration binder is not part of the shared framework.</summary>
    private static void Bind(IConfigurationSection section, EncryptedStorageOptions options)
    {
        if (section["Enabled"] is { } enabled)
            options.Enabled = bool.TryParse(enabled, out var value)
                ? value
                : throw new InvalidOperationException($"{EncryptedStorageOptions.SectionName}:Enabled must be true or false.");
        if (section["ActiveKeyId"] is { } activeKeyId)
            options.ActiveKeyId = activeKeyId;
        foreach (var key in section.GetSection("Keys").GetChildren().OrderBy(c => int.TryParse(c.Key, out var i) ? i : int.MaxValue))
            options.Keys.Add(new EncryptionKeyOptions { Id = key["Id"], Key = key["Key"], KeyFile = key["KeyFile"] });
    }
}
