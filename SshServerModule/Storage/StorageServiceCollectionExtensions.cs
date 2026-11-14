using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Storage
{
    public static class StorageServiceCollectionExtensions
    {
        /// <summary>
        /// The storage core: <see cref="IStorageProviderRegistry"/> over every registered <see cref="IStorageProvider"/>,
        /// the <see cref="IFileSystemFactory"/> of the sessions and the <see cref="IEffectivePermissionsService"/> of its
        /// permission decorator. Register at least one backend too, for example
        /// <c>services.AddLocalDiskStorage()</c>.
        /// </summary>
        public static IServiceCollection AddSshServerStorage(this IServiceCollection services)
        {
            services.TryAddSingleton<IStorageProviderRegistry, StorageProviderRegistry>();
            services.TryAddSingleton<IEffectivePermissionsService, EffectivePermissionsService>();
            services.TryAddSingleton<IFileSystemFactory, StorageFileSystemFactory>();
            return services;
        }
    }
}
