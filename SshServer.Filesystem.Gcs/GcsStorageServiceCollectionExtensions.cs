using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.Gcs;

public static class GcsStorageServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Google Cloud Storage provider ("gcs") in the storage provider registry. Nothing uses it until a
    /// storage configuration selects "gcs"; no client is created before that.
    /// </summary>
    public static IServiceCollection AddGcsStorage(this IServiceCollection services)
    {
        services.TryAddSingleton<GcsClientCache>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IStorageProvider, GcsStorageProvider>());
        return services;
    }
}
