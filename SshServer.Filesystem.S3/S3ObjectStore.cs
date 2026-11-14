using Amazon.S3;
using Amazon.S3.Model;

namespace SshServer.Filesystem.S3;

/// <summary>The size, write time and ETag of an object (HeadObject or a listing).</summary>
internal sealed record S3ObjectInfo(long Size, DateTime LastModifiedUtc, string ETag);

/// <summary>
/// The S3 requests of one storage location: the only class that builds SDK requests, so the bucket, the storage class
/// and the server-side encryption are set in one place. It throws the SDK exceptions; the callers translate them with
/// <see cref="S3Errors"/> and the virtual path.
/// </summary>
internal sealed class S3ObjectStore
{
    /// <summary>The largest object that one CopyObject (and one UploadPartCopy) can copy.</summary>
    public const long DefaultMaxCopySize = 5L * 1024 * 1024 * 1024;

    /// <summary>The most keys of one DeleteObjects request.</summary>
    private const int MaxDeleteKeys = 1000;

    private readonly IAmazonS3 _client;

    public S3ObjectStore(IAmazonS3 client, S3StorageOptions options, long maxCopySize = DefaultMaxCopySize)
    {
        _client = client;
        Options = options;
        MaxCopySize = maxCopySize;
    }

    public S3StorageOptions Options { get; }

    /// <summary>Larger objects are copied in parts (UploadPartCopy). A parameter only so the tests can use small objects.</summary>
    public long MaxCopySize { get; }

    private string Bucket => Options.Bucket;

    /// <summary>The object, or null when it does not exist.</summary>
    public async Task<S3ObjectInfo?> HeadAsync(string key, CancellationToken ct)
    {
        try
        {
            var response = await _client.GetObjectMetadataAsync(new GetObjectMetadataRequest { BucketName = Bucket, Key = key }, ct).ConfigureAwait(false);
            return new S3ObjectInfo(response.ContentLength, ToUtc(response.LastModified), response.ETag);
        }
        catch (AmazonS3Exception ex) when (S3Errors.IsNotFound(ex))
        {
            return null;
        }
    }

    /// <summary>The first objects whose keys start with <paramref name="prefix"/>, in key order (one page, no delimiter).</summary>
    public async Task<IReadOnlyList<S3Object>> FirstObjectsAsync(string prefix, int maxKeys, CancellationToken ct)
    {
        var page = await ListPageAsync(prefix, delimiter: null, continuationToken: null, maxKeys, ct).ConfigureAwait(false);
        return page.S3Objects ?? [];
    }

    public Task<ListObjectsV2Response> ListPageAsync(string prefix, string? delimiter, string? continuationToken, int? maxKeys, CancellationToken ct)
        => _client.ListObjectsV2Async(new ListObjectsV2Request
        {
            BucketName = Bucket,
            Prefix = prefix,
            Delimiter = delimiter,
            ContinuationToken = continuationToken,
            MaxKeys = maxKeys,
        }, ct);

    /// <summary>Every object whose key starts with <paramref name="prefix"/>, all pages.</summary>
    public async IAsyncEnumerable<S3Object> ListAllAsync(string prefix, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        string? token = null;
        do
        {
            var page = await ListPageAsync(prefix, delimiter: null, token, maxKeys: null, ct).ConfigureAwait(false);
            foreach (var item in page.S3Objects ?? [])
                yield return item;
            token = page.IsTruncated == true ? page.NextContinuationToken : null;
        }
        while (token != null);
    }

    public Task PutAsync(string key, byte[] data, int count, CancellationToken ct)
    {
        var request = new PutObjectRequest
        {
            BucketName = Bucket,
            Key = key,
            InputStream = new MemoryStream(data, 0, count, writable: false),
            AutoCloseStream = true,
        };
        if (StorageClass is { } storageClass)
            request.StorageClass = storageClass;
        if (Encryption is { } encryption)
        {
            request.ServerSideEncryptionMethod = encryption;
            request.ServerSideEncryptionKeyManagementServiceKeyId = KmsKeyId;
        }
        return _client.PutObjectAsync(request, ct);
    }

    public Task DeleteAsync(string key, CancellationToken ct)
        => _client.DeleteObjectAsync(new DeleteObjectRequest { BucketName = Bucket, Key = key }, ct);

    public async Task DeleteManyAsync(IReadOnlyList<string> keys, CancellationToken ct)
    {
        for (var start = 0; start < keys.Count; start += MaxDeleteKeys)
        {
            var request = new DeleteObjectsRequest
            {
                BucketName = Bucket,
                Objects = keys.Skip(start).Take(MaxDeleteKeys).Select(k => new KeyVersion { Key = k }).ToList(),
                Quiet = true,
            };
            var response = await _client.DeleteObjectsAsync(request, ct).ConfigureAwait(false);
            if (response.DeleteErrors is { Count: > 0 } errors)
                throw new AmazonS3Exception($"{errors.Count} objects could not be removed ({errors[0].Code}).");
        }
    }

    /// <summary>Copies an object on the server: CopyObject, or UploadPartCopy in parts when it is larger than <see cref="MaxCopySize"/>.</summary>
    public async Task CopyAsync(string sourceKey, string targetKey, S3ObjectInfo source, CancellationToken ct)
    {
        if (source.Size <= MaxCopySize)
        {
            var request = new CopyObjectRequest
            {
                SourceBucket = Bucket,
                SourceKey = sourceKey,
                DestinationBucket = Bucket,
                DestinationKey = targetKey,
                ETagToMatch = source.ETag,
            };
            if (StorageClass is { } storageClass)
                request.StorageClass = storageClass;
            if (Encryption is { } encryption)
            {
                request.ServerSideEncryptionMethod = encryption;
                request.ServerSideEncryptionKeyManagementServiceKeyId = KmsKeyId;
            }
            await _client.CopyObjectAsync(request, ct).ConfigureAwait(false);
            return;
        }

        var uploadId = await InitiateAsync(targetKey, ct).ConfigureAwait(false);
        try
        {
            var parts = await CopyPartsAsync(sourceKey, source, targetKey, uploadId, firstPartNumber: 1, ct).ConfigureAwait(false);
            await CompleteAsync(targetKey, uploadId, parts, ct).ConfigureAwait(false);
        }
        catch
        {
            await AbortAsync(targetKey, uploadId).ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Copies a whole object as the parts <paramref name="firstPartNumber"/>.. of a multipart upload, each at most <see cref="MaxCopySize"/>.</summary>
    public async Task<List<PartETag>> CopyPartsAsync(string sourceKey, S3ObjectInfo source, string targetKey, string uploadId, int firstPartNumber, CancellationToken ct)
    {
        var parts = new List<PartETag>();
        var partNumber = firstPartNumber;
        foreach (var (first, last) in CopyRanges(source.Size, MaxCopySize))
        {
            var response = await _client.CopyPartAsync(new CopyPartRequest
            {
                SourceBucket = Bucket,
                SourceKey = sourceKey,
                DestinationBucket = Bucket,
                DestinationKey = targetKey,
                UploadId = uploadId,
                PartNumber = partNumber,
                FirstByte = first,
                LastByte = last,
                ETagToMatch = [source.ETag],
            }, ct).ConfigureAwait(false);
            parts.Add(new PartETag(partNumber++, response.ETag));
        }
        return parts;
    }

    /// <summary>Splits <paramref name="size"/> bytes into equal ranges of at most <paramref name="maxRange"/> bytes (inclusive bounds).</summary>
    public static IEnumerable<(long First, long Last)> CopyRanges(long size, long maxRange)
    {
        var count = (size + maxRange - 1) / maxRange;
        var length = (size + count - 1) / count;
        for (long first = 0; first < size; first += length)
            yield return (first, Math.Min(first + length, size) - 1);
    }

    public async Task<string> InitiateAsync(string key, CancellationToken ct)
    {
        var request = new InitiateMultipartUploadRequest { BucketName = Bucket, Key = key };
        if (StorageClass is { } storageClass)
            request.StorageClass = storageClass;
        if (Encryption is { } encryption)
        {
            request.ServerSideEncryptionMethod = encryption;
            request.ServerSideEncryptionKeyManagementServiceKeyId = KmsKeyId;
        }
        var response = await _client.InitiateMultipartUploadAsync(request, ct).ConfigureAwait(false);
        return response.UploadId;
    }

    public async Task<PartETag> UploadPartAsync(string key, string uploadId, int partNumber, byte[] data, int count, CancellationToken ct)
    {
        var response = await _client.UploadPartAsync(new UploadPartRequest
        {
            BucketName = Bucket,
            Key = key,
            UploadId = uploadId,
            PartNumber = partNumber,
            InputStream = new MemoryStream(data, 0, count, writable: false),
            PartSize = count,
        }, ct).ConfigureAwait(false);
        return new PartETag(partNumber, response.ETag);
    }

    public Task CompleteAsync(string key, string uploadId, IEnumerable<PartETag> parts, CancellationToken ct)
        => _client.CompleteMultipartUploadAsync(new CompleteMultipartUploadRequest
        {
            BucketName = Bucket,
            Key = key,
            UploadId = uploadId,
            PartETags = parts.OrderBy(p => p.PartNumber).ToList(),
        }, ct);

    /// <summary>Aborts a multipart upload, so no part stays stored. Never throws: the upload already failed, and a
    /// bucket lifecycle rule (AbortIncompleteMultipartUpload) removes what an abort cannot.</summary>
    public async Task AbortAsync(string key, string uploadId)
    {
        try
        {
            await _client.AbortMultipartUploadAsync(new AbortMultipartUploadRequest { BucketName = Bucket, Key = key, UploadId = uploadId }, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex) when (S3Errors.Translate(ex, key, CancellationToken.None) != null)
        {
            // See above.
        }
    }

    /// <summary>Reads exactly <paramref name="destination"/>.Length bytes at <paramref name="offset"/> of the object with this ETag.</summary>
    public async Task ReadRangeAsync(string key, string eTag, long offset, Memory<byte> destination, CancellationToken ct)
    {
        using var response = await _client.GetObjectAsync(new GetObjectRequest
        {
            BucketName = Bucket,
            Key = key,
            ByteRange = new ByteRange(offset, offset + destination.Length - 1),
            EtagToMatch = eTag,
        }, ct).ConfigureAwait(false);
        await response.ResponseStream.ReadExactlyAsync(destination, ct).ConfigureAwait(false);
    }

    private S3StorageClass? StorageClass => string.IsNullOrEmpty(Options.StorageClass) ? null : S3StorageClass.FindValue(Options.StorageClass);

    private ServerSideEncryptionMethod? Encryption
        => string.IsNullOrEmpty(Options.ServerSideEncryption) ? null : ServerSideEncryptionMethod.FindValue(Options.ServerSideEncryption);

    private string? KmsKeyId => string.IsNullOrEmpty(Options.KmsKeyId) ? null : Options.KmsKeyId;

    public static DateTime ToUtc(DateTime? time) => time switch
    {
        null => DateTime.UnixEpoch,
        { Kind: DateTimeKind.Utc } utc => utc,
        { Kind: DateTimeKind.Local } local => local.ToUniversalTime(),
        { } unspecified => DateTime.SpecifyKind(unspecified, DateTimeKind.Utc),
    };
}
