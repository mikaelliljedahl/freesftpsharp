namespace SshServer.Filesystem.S3;

/// <summary>
/// The options of the S3 storage ("s3"): one bucket, or a key prefix in it, is "/" for the user. Works with AWS S3 and
/// with S3-compatible stores (MinIO, Cloudflare R2, Backblaze B2, Wasabi, DigitalOcean Spaces, ...) through
/// <see cref="Endpoint"/>. <see cref="ToString"/> never shows <see cref="SecretKey"/>.
/// </summary>
public sealed record S3StorageOptions
{
    public const int MiB = 1024 * 1024;

    /// <summary>The smallest part of a multipart upload that S3 accepts (except the last part).</summary>
    public const int MinUploadPartSize = 5 * MiB;

    /// <summary>The largest part that the server buffers in memory.</summary>
    public const int MaxUploadPartSize = 512 * MiB;

    public const int MaxUploadConcurrency = 64;
    public const int MinReadAheadSize = 64 * 1024;
    public const int MaxReadAheadSize = 512 * MiB;

    /// <summary>The bucket. It must exist; the server never creates or removes a bucket.</summary>
    public string Bucket { get; init; } = string.Empty;

    /// <summary>The key prefix that is "/" for the user, for example "users/alice"; empty for the whole bucket.</summary>
    public string? KeyPrefix { get; init; }

    /// <summary>The region, for example "eu-north-1". Empty: the region of the environment (AWS_REGION, profile).</summary>
    public string? Region { get; init; }

    /// <summary>The endpoint of an S3-compatible store, for example "http://localhost:9000". Empty for AWS S3.</summary>
    public string? Endpoint { get; init; }

    /// <summary>Path-style URLs (endpoint/bucket/key) instead of virtual-hosted URLs (bucket.endpoint/key); MinIO needs it.</summary>
    public bool ForcePathStyle { get; init; }

    /// <summary>The access key id. Empty: the credentials of the environment (environment variables, profile, instance role, IRSA).</summary>
    public string? AccessKey { get; init; }

    /// <summary>The secret access key; a secret, set together with <see cref="AccessKey"/>.</summary>
    public string? SecretKey { get; init; }

    /// <summary>The storage class of new objects, for example "STANDARD_IA". Empty: the default of the bucket.</summary>
    public string? StorageClass { get; init; }

    /// <summary>Server-side encryption of new objects: "AES256" or "aws:kms". Empty: the default of the bucket.</summary>
    public string? ServerSideEncryption { get; init; }

    /// <summary>The KMS key id for <see cref="ServerSideEncryption"/> "aws:kms". Empty: the AWS managed key.</summary>
    public string? KmsKeyId { get; init; }

    /// <summary>
    /// The size of one part of a multipart upload, buffered in memory. A file can have at most 10,000 parts, so the
    /// largest upload is 10,000 x this size (48.8 GiB with the default 5 MiB).
    /// </summary>
    public int UploadPartSize { get; init; } = MinUploadPartSize;

    /// <summary>The number of parts of one upload that are sent at the same time.</summary>
    public int UploadConcurrency { get; init; } = 2;

    /// <summary>The bytes that one read request fetches ahead, so a sequential download is one request per this size.</summary>
    public int ReadAheadSize { get; init; } = 4 * MiB;

    public override string ToString()
        => $"S3StorageOptions {{ Bucket = {Bucket}, KeyPrefix = {KeyPrefix}, Region = {Region}, Endpoint = {Endpoint}, " +
           $"ForcePathStyle = {ForcePathStyle}, AccessKey = {AccessKey}, SecretKey = {(string.IsNullOrEmpty(SecretKey) ? "" : "***")}, " +
           $"StorageClass = {StorageClass}, ServerSideEncryption = {ServerSideEncryption}, KmsKeyId = {KmsKeyId}, " +
           $"UploadPartSize = {UploadPartSize}, UploadConcurrency = {UploadConcurrency}, ReadAheadSize = {ReadAheadSize} }}";
}
