using System.Collections.Concurrent;
using Azure.Identity;
using Azure.Storage.Blobs;

namespace SshServer.Filesystem.AzureBlob;

/// <summary>The settings that make one container client: the same settings share one client (and its connections).</summary>
internal sealed record AzureBlobClientSettings(string? ConnectionString, string? SasUrl, string? AccountName, string? Endpoint, string? Container)
{
    public static AzureBlobClientSettings From(AzureBlobStorageOptions options) => new(
        NullIfEmpty(options.ConnectionString), NullIfEmpty(options.SasUrl), NullIfEmpty(options.AccountName),
        NullIfEmpty(options.Endpoint), NullIfEmpty(options.Container));

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    // The connection string and the SAS URL are secrets.
    public override string ToString() => $"AzureBlobClientSettings {{ AccountName = {AccountName}, Endpoint = {Endpoint}, Container = {Container} }}";
}

/// <summary>
/// The container clients of the storage provider, one per <see cref="AzureBlobClientSettings"/>, created at the first
/// use. A client is thread safe, so all sessions with the same settings share it. The identity of
/// <c>DefaultAzureCredential</c> is created once, at the first use of an account name.
/// </summary>
public sealed class AzureBlobClientCache
{
    private readonly ConcurrentDictionary<AzureBlobClientSettings, Lazy<BlobContainerClient>> _clients = new();
    private readonly Lazy<DefaultAzureCredential> _credential = new(() => new DefaultAzureCredential());
    private readonly Func<AzureBlobClientSettings, BlobContainerClient> _create;

    public AzureBlobClientCache()
    {
        _create = CreateClient;
    }

    internal AzureBlobClientCache(Func<AzureBlobClientSettings, BlobContainerClient> create)
    {
        _create = create;
    }

    /// <summary>The client for the account, container and credentials of <paramref name="options"/>.</summary>
    public BlobContainerClient Get(AzureBlobStorageOptions options)
    {
        var settings = AzureBlobClientSettings.From(options);
        return _clients.GetOrAdd(settings, s => new Lazy<BlobContainerClient>(() => _create(s))).Value;
    }

    private BlobContainerClient CreateClient(AzureBlobClientSettings settings)
    {
        if (settings.ConnectionString != null)
            return new BlobContainerClient(settings.ConnectionString, settings.Container);

        if (settings.SasUrl != null)
        {
            var sas = new Uri(settings.SasUrl);
            return settings.Container == null
                ? new BlobContainerClient(sas)
                : new BlobServiceClient(sas).GetBlobContainerClient(settings.Container);
        }

        var endpoint = settings.Endpoint?.TrimEnd('/') ?? $"https://{settings.AccountName}.blob.core.windows.net";
        return new BlobContainerClient(new Uri($"{endpoint}/{settings.Container}"), _credential.Value);
    }
}
