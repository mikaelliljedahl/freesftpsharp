using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.LocalDisk;

public static class LocalDiskStorageServiceCollectionExtensions
{
    /// <summary>
    /// Registers the local disk storage provider ("local") in the storage provider registry, and the local disk at
    /// <c>User.UserRootDirectory</c> as the storage of a user without a storage configuration (<see cref="IDefaultUserStorage"/>).
    /// </summary>
    public static IServiceCollection AddLocalDiskStorage(this IServiceCollection services)
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IStorageProvider, LocalDiskStorageProvider>());
        services.TryAddSingleton<IDefaultUserStorage, UserRootDefaultStorage>();
        return services;
    }
}
