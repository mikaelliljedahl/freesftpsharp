using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Storage
{
    public static class StorageServiceCollectionExtensions
    {
        /// <summary>
        /// The storage core: <see cref="IStorageProviderRegistry"/> over every registered <see cref="IStorageProvider"/>,
        /// the <see cref="IFileSystemFactory"/> of the sessions, the <see cref="IUserStorageResolver"/> (per-user storage and
        /// virtual folders), the <see cref="StorageOptionsCodec"/>, the <see cref="IEffectivePermissionsService"/> of the
        /// permission decorator, and the application services of the admin UI (<see cref="StorageConfigService"/>,
        /// <see cref="VirtualFolderService"/>). Register at least one backend too, for example
        /// <c>services.AddLocalDiskStorage()</c>. Without a registered <see cref="ISecretProtector"/> (AddSshServerSettings
        /// registers one) a storage configuration cannot have secrets.
        /// </summary>
        public static IServiceCollection AddSshServerStorage(this IServiceCollection services)
        {
            services.TryAddSingleton<IStorageProviderRegistry, StorageProviderRegistry>();
            services.TryAddSingleton<IEffectivePermissionsService, EffectivePermissionsService>();
            services.TryAddSingleton<IFileSystemFactory, StorageFileSystemFactory>();
            services.TryAddSingleton<IUserStorageResolver, UserStorageResolver>();
            services.TryAddSingleton<ISecretProtector, UnavailableSecretProtector>();
            services.TryAddSingleton<StorageOptionsCodec>();
            services.TryAddSingleton<StorageConfigService>();
            services.TryAddSingleton<VirtualFolderService>();
            return services;
        }
    }
}
