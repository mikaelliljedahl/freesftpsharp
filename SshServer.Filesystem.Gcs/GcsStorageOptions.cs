namespace SshServer.Filesystem.Gcs;

/// <summary>
/// The options of the Google Cloud Storage storage ("gcs"): one bucket, or a key prefix in it, is "/" for the user.
/// <see cref="ToString"/> never shows <see cref="CredentialsJson"/>.
/// </summary>
public sealed record GcsStorageOptions
{
    public const int KiB = 1024;
    public const int MiB = 1024 * KiB;

    /// <summary>The chunks of a resumable upload are a multiple of this size (a rule of Cloud Storage).</summary>
    public const int UploadChunkGranularity = 256 * KiB;

    public const int MinUploadChunkSize = UploadChunkGranularity;

    /// <summary>The largest chunk that the server buffers in memory.</summary>
    public const int MaxUploadChunkSize = 512 * MiB;

    public const int MinReadAheadSize = 64 * KiB;
    public const int MaxReadAheadSize = 512 * MiB;

    /// <summary>The bucket. It must exist; the server never creates or removes a bucket.</summary>
    public string Bucket { get; init; } = string.Empty;

    /// <summary>The key prefix that is "/" for the user, for example "users/alice"; empty for the whole bucket.</summary>
    public string? KeyPrefix { get; init; }

    /// <summary>
    /// The content of a service account key file (JSON), a secret. Empty (and no <see cref="CredentialsFile"/>): the
    /// Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS, gcloud login, the service account of the VM or pod).
    /// </summary>
    public string? CredentialsJson { get; init; }

    /// <summary>The path of a service account key file on the server. Not together with <see cref="CredentialsJson"/>.</summary>
    public string? CredentialsFile { get; init; }

    /// <summary>
    /// The endpoint of an emulator such as fake-gcs-server, for example "http://localhost:4443". Without credentials the
    /// requests are then not authenticated. Empty for Google Cloud Storage.
    /// </summary>
    public string? Endpoint { get; init; }

    /// <summary>The storage class of new objects: STANDARD, NEARLINE, COLDLINE or ARCHIVE. Empty: the default of the bucket.</summary>
    public string? StorageClass { get; init; }

    /// <summary>
    /// The size of one chunk of a resumable upload, buffered in memory (a multiple of 256 KiB). A file smaller than one
    /// chunk is one request. There is no limit for the number of chunks.
    /// </summary>
    public int UploadChunkSize { get; init; } = 8 * MiB;

    /// <summary>The bytes that one read request fetches ahead, so a sequential download is one request per this size.</summary>
    public int ReadAheadSize { get; init; } = 4 * MiB;

    public override string ToString()
        => $"GcsStorageOptions {{ Bucket = {Bucket}, KeyPrefix = {KeyPrefix}, CredentialsJson = {(string.IsNullOrEmpty(CredentialsJson) ? "" : "***")}, " +
           $"CredentialsFile = {CredentialsFile}, Endpoint = {Endpoint}, StorageClass = {StorageClass}, " +
           $"UploadChunkSize = {UploadChunkSize}, ReadAheadSize = {ReadAheadSize} }}";
}
