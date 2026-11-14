using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.S3;

public static class S3StorageServiceCollectionExtensions
{
    /// <summary>
    /// Registers the S3 storage provider ("s3") in the storage provider registry. Nothing uses it until a storage
    /// configuration selects "s3"; no S3 client is created before that.
    /// </summary>
    public static IServiceCollection AddS3Storage(this IServiceCollection services)
    {
        services.TryAddSingleton<S3ClientCache>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IStorageProvider, S3StorageProvider>());
        return services;
    }
}
