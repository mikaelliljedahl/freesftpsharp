using Azure.Identity;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.AzureBlob;

/// <summary>The Azure Blob storage ("azure-blob"): an <see cref="AzureBlobFileSystem"/> on one container or name prefix.</summary>
public sealed class AzureBlobStorageProvider : StorageProvider<AzureBlobStorageOptions>
{
    public const string ProviderName = "azure-blob";

    private static readonly string[] Tiers = ["Hot", "Cool", "Cold"];

    private readonly AzureBlobClientCache _clients;

    public AzureBlobStorageProvider(AzureBlobClientCache clients)
    {
        _clients = clients;
    }

    public override string Name => ProviderName;

    protected override IReadOnlyList<string> ValidateOptions(AzureBlobStorageOptions options)
    {
        var problems = new List<string>();

        var connectionString = !string.IsNullOrWhiteSpace(options.ConnectionString);
        var sasUrl = !string.IsNullOrWhiteSpace(options.SasUrl);
        var account = !string.IsNullOrWhiteSpace(options.AccountName);
        if (new[] { connectionString, sasUrl, account }.Count(set => set) != 1)
            problems.Add("Set exactly one of the connection string, the SAS URL and the account name (managed identity).");

        if (string.IsNullOrWhiteSpace(options.Container))
        {
            if (!sasUrl)
                problems.Add("The container is not set.");
        }
        else if (options.Container.Any(c => c == '/' || char.IsWhiteSpace(c)))
        {
            problems.Add("The container name cannot contain '/' or spaces.");
        }

        if (options.KeyPrefix is { } prefix
            && (prefix.Contains('\\') || prefix.Split('/').Any(segment => segment is "." or "..")))
            problems.Add("The key prefix cannot contain '\\', '.' or '..' segments.");

        if (sasUrl && !IsHttpUrl(options.SasUrl!))
            problems.Add("The SAS URL must be an absolute http or https URL.");

        if (!string.IsNullOrWhiteSpace(options.Endpoint))
        {
            if (!account)
                problems.Add("The endpoint is used only with the account name; a connection string or a SAS URL has the address inside.");
            if (!IsHttpUrl(options.Endpoint))
                problems.Add("The endpoint must be an absolute http or https URL.");
        }

        if (account && (options.AccountName!.Any(c => c == '/' || char.IsWhiteSpace(c))))
            problems.Add("The account name cannot contain '/' or spaces.");

        if (!string.IsNullOrEmpty(options.AccessTier) && !Tiers.Contains(options.AccessTier))
            problems.Add("The access tier must be Hot, Cool or Cold.");

        if (options.UploadBlockSize is < AzureBlobStorageOptions.MinUploadBlockSize or > AzureBlobStorageOptions.MaxUploadBlockSize)
            problems.Add($"The upload block size must be from {AzureBlobStorageOptions.MinUploadBlockSize} to {AzureBlobStorageOptions.MaxUploadBlockSize} bytes.");
        if (options.UploadConcurrency is < 1 or > AzureBlobStorageOptions.MaxUploadConcurrency)
            problems.Add($"The upload concurrency must be from 1 to {AzureBlobStorageOptions.MaxUploadConcurrency}.");
        if (options.ReadAheadSize is < AzureBlobStorageOptions.MinReadAheadSize or > AzureBlobStorageOptions.MaxReadAheadSize)
            problems.Add($"The read-ahead size must be from {AzureBlobStorageOptions.MinReadAheadSize} to {AzureBlobStorageOptions.MaxReadAheadSize} bytes.");
        return problems;
    }

    protected override ValueTask<IFileSystem> CreateFileSystemAsync(AzureBlobStorageOptions options, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            return ValueTask.FromResult<IFileSystem>(new AzureBlobFileSystem(_clients.Get(options), options));
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or UriFormatException or CredentialUnavailableException)
        {
            // For example a connection string that the SDK cannot parse. The message of the SDK can hold a part of the secret, so it is not repeated.
            throw new ArgumentException($"The Azure Blob client cannot be created ({ex.GetType().Name}): check the connection string, the SAS URL and the account name.", nameof(options));
        }
    }

    private static bool IsHttpUrl(string value)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https";
}
