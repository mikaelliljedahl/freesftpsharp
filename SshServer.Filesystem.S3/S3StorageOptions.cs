using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using SshServer.Interfaces.Security;

namespace SshServer.Filesystem.S3;

/// <summary>
/// The options of the S3 storage ("s3"): one bucket, or a key prefix in it, is "/" for the user. Works with AWS S3 and
/// with S3-compatible stores (MinIO, Cloudflare R2, Backblaze B2, Wasabi, DigitalOcean Spaces, ...) through
/// <see cref="Endpoint"/>. <see cref="ToString"/> never shows <see cref="SecretKey"/>, and it is stored encrypted
/// (<see cref="SecretAttribute"/>). The attributes describe the fields of the admin UI.
/// </summary>
[DisplayName("S3 (AWS or S3-compatible)")]
[Description("A bucket, or a key prefix in it, on AWS S3 or an S3-compatible store such as MinIO, Cloudflare R2, Backblaze B2 or Wasabi.")]
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
    [Display(Name = "Bucket", Description = "The bucket must exist; the server never creates or removes a bucket.", Prompt = "my-bucket", Order = 1)]
    public string Bucket { get; init; } = string.Empty;

    /// <summary>The key prefix that is "/" for the user, for example "users/alice"; empty for the whole bucket.</summary>
    [Display(Name = "Key prefix", Description = "The prefix that is / for the client, for example users/alice. Empty: the whole bucket.", Prompt = "users/alice", Order = 2)]
    public string? KeyPrefix { get; init; }

    /// <summary>The region, for example "eu-north-1". Empty: the region of the environment (AWS_REGION, profile).</summary>
    [Display(Name = "Region", Description = "Empty: the region of the environment (AWS_REGION, profile).", Prompt = "eu-north-1", Order = 3)]
    public string? Region { get; init; }

    /// <summary>The endpoint of an S3-compatible store, for example "http://localhost:9000". Empty for AWS S3.</summary>
    [Display(Name = "Endpoint", Description = "The URL of an S3-compatible store. Empty for AWS S3.", Prompt = "http://localhost:9000", Order = 4)]
    public string? Endpoint { get; init; }

    /// <summary>Path-style URLs (endpoint/bucket/key) instead of virtual-hosted URLs (bucket.endpoint/key); MinIO needs it.</summary>
    [Display(Name = "Path-style URLs", Description = "endpoint/bucket/key instead of bucket.endpoint/key; MinIO needs it.", Order = 5)]
    public bool ForcePathStyle { get; init; }

    /// <summary>The access key id. Empty: the credentials of the environment (environment variables, profile, instance role, IRSA).</summary>
    [Display(Name = "Access key id", Description = "Empty: the credentials of the environment (variables, profile, instance role, IRSA).", Order = 6)]
    public string? AccessKey { get; init; }

    /// <summary>The secret access key; a secret, set together with <see cref="AccessKey"/>.</summary>
    [Secret]
    [Display(Name = "Secret access key", Description = "Set together with the access key id. It is stored encrypted and never shown again.", Order = 7)]
    public string? SecretKey { get; init; }

    /// <summary>The storage class of new objects, for example "STANDARD_IA". Empty: the default of the bucket.</summary>
    [Display(Name = "Storage class", Description = "The storage class of new objects. Empty: the default of the bucket.", Prompt = "STANDARD_IA", Order = 8)]
    public string? StorageClass { get; init; }

    /// <summary>Server-side encryption of new objects: "AES256" or "aws:kms". Empty: the default of the bucket.</summary>
    [AllowedValues("", "AES256", "aws:kms")]
    [Display(Name = "Server-side encryption", Description = "Of new objects. Empty: the default of the bucket.", Order = 9)]
    public string? ServerSideEncryption { get; init; }

    /// <summary>The KMS key id for <see cref="ServerSideEncryption"/> "aws:kms". Empty: the AWS managed key.</summary>
    [Display(Name = "KMS key id", Description = "For aws:kms. Empty: the AWS managed key.", Order = 10)]
    public string? KmsKeyId { get; init; }

    /// <summary>
    /// The size of one part of a multipart upload, buffered in memory. A file can have at most 10,000 parts, so the
    /// largest upload is 10,000 x this size (48.8 GiB with the default 5 MiB).
    /// </summary>
    [Display(Name = "Upload part size (bytes)", Description = "One part of a multipart upload, buffered in memory. The largest file is 10,000 parts.", Order = 11)]
    public int UploadPartSize { get; init; } = MinUploadPartSize;

    /// <summary>The number of parts of one upload that are sent at the same time.</summary>
    [Display(Name = "Upload concurrency", Description = "The parts of one upload that are sent at the same time.", Order = 12)]
    public int UploadConcurrency { get; init; } = 2;

    /// <summary>The bytes that one read request fetches ahead, so a sequential download is one request per this size.</summary>
    [Display(Name = "Read-ahead size (bytes)", Description = "The bytes that one read request fetches ahead.", Order = 13)]
    public int ReadAheadSize { get; init; } = 4 * MiB;

    public override string ToString()
        => $"S3StorageOptions {{ Bucket = {Bucket}, KeyPrefix = {KeyPrefix}, Region = {Region}, Endpoint = {Endpoint}, " +
           $"ForcePathStyle = {ForcePathStyle}, AccessKey = {AccessKey}, SecretKey = {(string.IsNullOrEmpty(SecretKey) ? "" : "***")}, " +
           $"StorageClass = {StorageClass}, ServerSideEncryption = {ServerSideEncryption}, KmsKeyId = {KmsKeyId}, " +
           $"UploadPartSize = {UploadPartSize}, UploadConcurrency = {UploadConcurrency}, ReadAheadSize = {ReadAheadSize} }}";
}
