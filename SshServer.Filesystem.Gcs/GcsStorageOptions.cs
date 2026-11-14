using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using SshServer.Interfaces.Security;

namespace SshServer.Filesystem.Gcs;

/// <summary>
/// The options of the Google Cloud Storage storage ("gcs"): one bucket, or a key prefix in it, is "/" for the user.
/// <see cref="ToString"/> never shows <see cref="CredentialsJson"/>, and it is stored encrypted (<see cref="SecretAttribute"/>).
/// The attributes describe the fields of the admin UI.
/// </summary>
[DisplayName("Google Cloud Storage")]
[Description("A bucket, or a key prefix in it, on Google Cloud Storage.")]
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
    [Display(Name = "Bucket", Description = "The bucket must exist; the server never creates or removes a bucket.", Prompt = "my-bucket", Order = 1)]
    public string Bucket { get; init; } = string.Empty;

    /// <summary>The key prefix that is "/" for the user, for example "users/alice"; empty for the whole bucket.</summary>
    [Display(Name = "Key prefix", Description = "The prefix that is / for the client, for example users/alice. Empty: the whole bucket.", Prompt = "users/alice", Order = 2)]
    public string? KeyPrefix { get; init; }

    /// <summary>
    /// The content of a service account key file (JSON), a secret. Empty (and no <see cref="CredentialsFile"/>): the
    /// Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS, gcloud login, the service account of the VM or pod).
    /// </summary>
    [Secret]
    [Display(Name = "Service account key (JSON)", Description = "The content of a key file. It is stored encrypted and never shown again. Empty: the Application Default Credentials.", Order = 3)]
    public string? CredentialsJson { get; init; }

    /// <summary>The path of a service account key file on the server. Not together with <see cref="CredentialsJson"/>.</summary>
    [Display(Name = "Service account key file", Description = "A key file on the server, instead of the JSON.", Order = 4)]
    public string? CredentialsFile { get; init; }

    /// <summary>
    /// The endpoint of an emulator such as fake-gcs-server, for example "http://localhost:4443". Without credentials the
    /// requests are then not authenticated. Empty for Google Cloud Storage.
    /// </summary>
    [Display(Name = "Endpoint", Description = "The URL of an emulator. Empty for Google Cloud Storage.", Prompt = "http://localhost:4443", Order = 5)]
    public string? Endpoint { get; init; }

    /// <summary>The storage class of new objects: STANDARD, NEARLINE, COLDLINE or ARCHIVE. Empty: the default of the bucket.</summary>
    [Display(Name = "Storage class", Description = "STANDARD, NEARLINE, COLDLINE or ARCHIVE. Empty: the default of the bucket.", Order = 6)]
    public string? StorageClass { get; init; }

    /// <summary>
    /// The size of one chunk of a resumable upload, buffered in memory (a multiple of 256 KiB). A file smaller than one
    /// chunk is one request. There is no limit for the number of chunks.
    /// </summary>
    [Display(Name = "Upload chunk size (bytes)", Description = "A multiple of 256 KiB, buffered in memory.", Order = 7)]
    public int UploadChunkSize { get; init; } = 8 * MiB;

    /// <summary>The bytes that one read request fetches ahead, so a sequential download is one request per this size.</summary>
    [Display(Name = "Read-ahead size (bytes)", Description = "The bytes that one read request fetches ahead.", Order = 8)]
    public int ReadAheadSize { get; init; } = 4 * MiB;

    public override string ToString()
        => $"GcsStorageOptions {{ Bucket = {Bucket}, KeyPrefix = {KeyPrefix}, CredentialsJson = {(string.IsNullOrEmpty(CredentialsJson) ? "" : "***")}, " +
           $"CredentialsFile = {CredentialsFile}, Endpoint = {Endpoint}, StorageClass = {StorageClass}, " +
           $"UploadChunkSize = {UploadChunkSize}, ReadAheadSize = {ReadAheadSize} }}";
}
