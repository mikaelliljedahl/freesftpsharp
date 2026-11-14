using Amazon.Runtime;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.S3;

/// <summary>The S3 storage ("s3"): an <see cref="S3FileSystem"/> on one bucket or key prefix.</summary>
public sealed class S3StorageProvider : StorageProvider<S3StorageOptions>
{
    public const string ProviderName = "s3";

    private static readonly string[] Encryptions = ["AES256", "aws:kms"];

    private readonly S3ClientCache _clients;

    public S3StorageProvider(S3ClientCache clients)
    {
        _clients = clients;
    }

    public override string Name => ProviderName;

    protected override IReadOnlyList<string> ValidateOptions(S3StorageOptions options)
    {
        var problems = new List<string>();
        if (string.IsNullOrWhiteSpace(options.Bucket))
            problems.Add("The bucket is not set.");
        else if (options.Bucket.Any(c => c == '/' || char.IsWhiteSpace(c)))
            problems.Add("The bucket name cannot contain '/' or spaces.");

        if (options.KeyPrefix is { } prefix
            && (prefix.Contains('\\') || prefix.Split('/').Any(segment => segment is "." or "..")))
            problems.Add("The key prefix cannot contain '\\', '.' or '..' segments.");

        if (!string.IsNullOrWhiteSpace(options.Endpoint)
            && (!Uri.TryCreate(options.Endpoint, UriKind.Absolute, out var endpoint) || endpoint.Scheme is not ("http" or "https")))
            problems.Add("The endpoint must be an absolute http or https URL.");

        if (string.IsNullOrWhiteSpace(options.AccessKey) != string.IsNullOrWhiteSpace(options.SecretKey))
            problems.Add("Set both the access key and the secret key, or neither (credentials of the environment).");

        if (!string.IsNullOrEmpty(options.ServerSideEncryption) && !Encryptions.Contains(options.ServerSideEncryption))
            problems.Add("The server-side encryption must be AES256 or aws:kms.");
        if (!string.IsNullOrEmpty(options.KmsKeyId) && options.ServerSideEncryption != "aws:kms")
            problems.Add("A KMS key id needs the server-side encryption aws:kms.");

        if (options.UploadPartSize is < S3StorageOptions.MinUploadPartSize or > S3StorageOptions.MaxUploadPartSize)
            problems.Add($"The upload part size must be from {S3StorageOptions.MinUploadPartSize} to {S3StorageOptions.MaxUploadPartSize} bytes.");
        if (options.UploadConcurrency is < 1 or > S3StorageOptions.MaxUploadConcurrency)
            problems.Add($"The upload concurrency must be from 1 to {S3StorageOptions.MaxUploadConcurrency}.");
        if (options.ReadAheadSize is < S3StorageOptions.MinReadAheadSize or > S3StorageOptions.MaxReadAheadSize)
            problems.Add($"The read-ahead size must be from {S3StorageOptions.MinReadAheadSize} to {S3StorageOptions.MaxReadAheadSize} bytes.");
        return problems;
    }

    protected override ValueTask<IFileSystem> CreateFileSystemAsync(S3StorageOptions options, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            return ValueTask.FromResult<IFileSystem>(new S3FileSystem(_clients.Get(options), options));
        }
        catch (AmazonClientException ex)
        {
            // For example no region in the options and none in the environment.
            throw new ArgumentException($"The S3 client cannot be created: {ex.Message}", nameof(options), ex);
        }
    }
}
