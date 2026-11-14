using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.AzureBlob;

public static class AzureBlobStorageServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Azure Blob storage provider ("azure-blob") in the storage provider registry. Nothing uses it until a
    /// storage configuration selects "azure-blob"; no client is created before that.
    /// </summary>
    public static IServiceCollection AddAzureBlobStorage(this IServiceCollection services)
    {
        services.TryAddSingleton<AzureBlobClientCache>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IStorageProvider, AzureBlobStorageProvider>());
        return services;
    }
}
