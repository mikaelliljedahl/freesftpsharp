using System.Text.Json;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.Gcs;

/// <summary>The Google Cloud Storage storage ("gcs"): a <see cref="GcsFileSystem"/> on one bucket or key prefix.</summary>
public sealed class GcsStorageProvider : StorageProvider<GcsStorageOptions>
{
    public const string ProviderName = "gcs";

    private static readonly string[] StorageClasses = ["STANDARD", "NEARLINE", "COLDLINE", "ARCHIVE"];

    private readonly GcsClientCache _clients;

    public GcsStorageProvider(GcsClientCache clients)
    {
        _clients = clients;
    }

    public override string Name => ProviderName;

    protected override IReadOnlyList<string> ValidateOptions(GcsStorageOptions options)
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

        var hasJson = !string.IsNullOrWhiteSpace(options.CredentialsJson);
        if (hasJson && !string.IsNullOrWhiteSpace(options.CredentialsFile))
            problems.Add("Set the credentials JSON or the credentials file, not both.");
        if (hasJson && !IsJsonObject(options.CredentialsJson!))
            problems.Add("The credentials JSON is not a JSON object (the content of a service account key file).");

        if (!string.IsNullOrEmpty(options.StorageClass) && !StorageClasses.Contains(options.StorageClass))
            problems.Add("The storage class must be STANDARD, NEARLINE, COLDLINE or ARCHIVE.");

        if (options.UploadChunkSize is < GcsStorageOptions.MinUploadChunkSize or > GcsStorageOptions.MaxUploadChunkSize
            || options.UploadChunkSize % GcsStorageOptions.UploadChunkGranularity != 0)
            problems.Add($"The upload chunk size must be a multiple of {GcsStorageOptions.UploadChunkGranularity} bytes from {GcsStorageOptions.MinUploadChunkSize} to {GcsStorageOptions.MaxUploadChunkSize} bytes.");
        if (options.ReadAheadSize is < GcsStorageOptions.MinReadAheadSize or > GcsStorageOptions.MaxReadAheadSize)
            problems.Add($"The read-ahead size must be from {GcsStorageOptions.MinReadAheadSize} to {GcsStorageOptions.MaxReadAheadSize} bytes.");
        return problems;
    }

    protected override ValueTask<IFileSystem> CreateFileSystemAsync(GcsStorageOptions options, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            return ValueTask.FromResult<IFileSystem>(new GcsFileSystem(_clients.Get(options), options));
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or JsonException or UnauthorizedAccessException)
        {
            // For example no Application Default Credentials, or a credentials file that cannot be read.
            throw new ArgumentException($"The Google Cloud Storage client cannot be created: {ex.Message}", nameof(options), ex);
        }
    }

    private static bool IsJsonObject(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            return document.RootElement.ValueKind == JsonValueKind.Object;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
