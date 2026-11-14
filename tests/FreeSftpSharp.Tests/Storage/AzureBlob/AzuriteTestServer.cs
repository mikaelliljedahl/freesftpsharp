using Azure.Storage;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using Azure.Storage.Sas;
using SshServer.Filesystem.AzureBlob;

namespace FreeSftpSharp.Tests.Storage.AzureBlob;

/// <summary>
/// The real Azure Blob server of the Azure tests (Azurite in CI): FREESFTPSHARP_TEST_AZURITE is the address of its blob
/// service (for example http://127.0.0.1:10000). The account is the well-known development account of Azurite
/// (devstoreaccount1, with its published key). FREESFTPSHARP_TEST_AZURITE_CONTAINER (default freesftpsharp-tests) is
/// created when it is missing. Without the address the tests are skipped.
/// </summary>
internal static class AzuriteTestServer
{
    public const string EndpointVariable = "FREESFTPSHARP_TEST_AZURITE";

    public const string AccountName = "devstoreaccount1";

    /// <summary>The published key of the Azurite development account; it protects nothing.</summary>
    private const string AccountKey = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

    private static readonly Lazy<BlobContainerClient> LazyContainer = new(CreateContainer);

    public static string? Endpoint => NullIfEmpty(Environment.GetEnvironmentVariable(EndpointVariable))?.TrimEnd('/');

    public static string Container => NullIfEmpty(Environment.GetEnvironmentVariable("FREESFTPSHARP_TEST_AZURITE_CONTAINER")) ?? "freesftpsharp-tests";

    public static string ConnectionString
        => $"DefaultEndpointsProtocol=http;AccountName={AccountName};AccountKey={AccountKey};BlobEndpoint={Endpoint}/{AccountName};";

    public static void SkipIfUnavailable()
    {
        if (Endpoint == null)
            Assert.Skip($"{EndpointVariable} is not set (Azurite is needed).");
    }

    /// <summary>The options of a user root below <paramref name="keyPrefix"/>, with the connection string of the test server.</summary>
    public static AzureBlobStorageOptions Options(string keyPrefix) => new()
    {
        Container = Container,
        KeyPrefix = keyPrefix,
        ConnectionString = ConnectionString,
    };

    /// <summary>A SAS URL of the container with the rights of a user root (read, add, create, write, delete, list).</summary>
    public static string SasUrl()
    {
        var sas = new BlobSasBuilder(BlobContainerSasPermissions.All, DateTimeOffset.UtcNow.AddHours(1)) { BlobContainerName = Container, Protocol = SasProtocol.HttpsAndHttp };
        var credential = new StorageSharedKeyCredential(AccountName, AccountKey);
        return $"{Endpoint}/{AccountName}/{Container}?{sas.ToSasQueryParameters(credential)}";
    }

    /// <summary>A client of the container; the container exists.</summary>
    public static BlobContainerClient Client => LazyContainer.Value;

    /// <summary>
    /// Creates the container when it is missing (once per test run). A test that reaches the server through its own
    /// client (for example the SFTP server of the end-to-end tests) calls this first.
    /// </summary>
    public static void EnsureContainer() => _ = LazyContainer.Value;

    /// <summary>Removes every blob below a name prefix (cleanup; errors are ignored).</summary>
    public static void DeletePrefix(string keyPrefix)
    {
        try
        {
            foreach (var blob in Client.GetBlobs(BlobTraits.None, BlobStates.None, keyPrefix.TrimEnd('/') + "/", default).ToList())
                Client.DeleteBlobIfExists(blob.Name, DeleteSnapshotsOption.IncludeSnapshots);
        }
        catch (Exception)
        {
            // Cleanup must not fail a test.
        }
    }

    /// <summary>The blobs that are committed, by name. Uncommitted blocks do not show up.</summary>
    public static List<string> BlobNames(string keyPrefix)
        => Client.GetBlobs(BlobTraits.None, BlobStates.None, keyPrefix.TrimEnd('/') + "/", default).Select(b => b.Name).ToList();

    /// <summary>The ids of the uncommitted blocks of a blob that does not exist yet (staged blocks that were never committed).</summary>
    public static async Task<int> CountUncommittedBlocksAsync(string name)
    {
        var response = await Client.GetBlockBlobClient(name).GetBlockListAsync(BlockListTypes.Uncommitted);
        return response.Value.UncommittedBlocks.Count();
    }

    private static BlobContainerClient CreateContainer()
    {
        var client = new BlobContainerClient(ConnectionString, Container);
        client.CreateIfNotExists();
        return client;
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
