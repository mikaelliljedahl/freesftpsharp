using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;

namespace FreeSftpSharp.Tests.Storage.S3;

/// <summary>
/// An S3 bucket in memory for the unit tests of the S3 backend: the requests that <c>S3FileSystem</c> sends, with the
/// semantics of S3 (flat keys in ordinal order, ListObjectsV2 with delimiter and paging, ranged GetObject with
/// If-Match, CopyObject, multipart uploads with the multipart ETag, 404/412/416 errors). Every request is counted in
/// <see cref="Calls"/> and kept in <see cref="Requests"/>; <see cref="Fail"/> makes chosen requests fail. Every other
/// request of the base client goes to an address where nothing listens.
/// </summary>
public sealed class FakeS3Client : AmazonS3Client
{
    private readonly Lock _lock = new();
    private readonly SortedDictionary<string, StoredObject> _objects = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SortedDictionary<int, byte[]>> _uploads = [];

    public FakeS3Client()
        : base(new AnonymousAWSCredentials(), new AmazonS3Config { ServiceURL = "http://127.0.0.1:9", ForcePathStyle = true })
    {
    }

    /// <summary>The most entries of one ListObjectsV2 page (S3: 1000).</summary>
    public int PageSize { get; set; } = 1000;

    /// <summary>The number of requests per operation, for example "GetObject".</summary>
    public ConcurrentDictionary<string, int> Calls { get; } = new();

    /// <summary>Every request, in order.</summary>
    public ConcurrentQueue<AmazonWebServiceRequest> Requests { get; } = new();

    /// <summary>Called with the operation and the request before it runs; an exception that it returns is thrown.</summary>
    public Func<string, AmazonWebServiceRequest, Exception?>? Fail { get; set; }

    public int CallCount(string operation) => Calls.GetValueOrDefault(operation);

    public IReadOnlyList<string> Keys
    {
        get { lock (_lock) return _objects.Keys.ToList(); }
    }

    public int OpenUploads
    {
        get { lock (_lock) return _uploads.Count; }
    }

    public byte[] Content(string key)
    {
        lock (_lock) return _objects[key].Data;
    }

    public string ETagOf(string key)
    {
        lock (_lock) return _objects[key].ETag;
    }

    public void Seed(string key, byte[] data)
    {
        lock (_lock) _objects[key] = new StoredObject(data, Quote(Md5Hex(data)), DateTime.UtcNow);
    }

    public static AmazonS3Exception Error(HttpStatusCode status, string code)
        => new($"Fake S3 error {code}", ErrorType.Sender, code, "fake-request-id", status);

    public override Task<GetObjectMetadataResponse> GetObjectMetadataAsync(GetObjectMetadataRequest request, CancellationToken cancellationToken = default)
    {
        Begin("HeadObject", request, cancellationToken);
        lock (_lock)
        {
            if (!_objects.TryGetValue(request.Key, out var stored))
                throw Error(HttpStatusCode.NotFound, "NotFound");
            return Task.FromResult(new GetObjectMetadataResponse
            {
                ContentLength = stored.Data.Length,
                ETag = stored.ETag,
                LastModified = stored.LastModified,
                HttpStatusCode = HttpStatusCode.OK,
            });
        }
    }

    public override Task<GetObjectResponse> GetObjectAsync(GetObjectRequest request, CancellationToken cancellationToken = default)
    {
        Begin("GetObject", request, cancellationToken);
        lock (_lock)
        {
            if (!_objects.TryGetValue(request.Key, out var stored))
                throw Error(HttpStatusCode.NotFound, "NoSuchKey");
            if (request.EtagToMatch != null && request.EtagToMatch != stored.ETag)
                throw Error(HttpStatusCode.PreconditionFailed, "PreconditionFailed");

            var start = request.ByteRange?.Start ?? 0;
            var end = Math.Min(request.ByteRange?.End ?? stored.Data.Length - 1, stored.Data.Length - 1);
            if (start >= stored.Data.Length)
                throw Error(HttpStatusCode.RequestedRangeNotSatisfiable, "InvalidRange");
            var slice = stored.Data.AsSpan((int)start, (int)(end - start + 1)).ToArray();
            return Task.FromResult(new GetObjectResponse
            {
                ResponseStream = new MemoryStream(slice),
                ContentLength = slice.Length,
                ETag = stored.ETag,
                HttpStatusCode = HttpStatusCode.PartialContent,
            });
        }
    }

    public override Task<PutObjectResponse> PutObjectAsync(PutObjectRequest request, CancellationToken cancellationToken = default)
    {
        Begin("PutObject", request, cancellationToken);
        var data = ReadAll(request.InputStream);
        Seed(request.Key, data);
        return Task.FromResult(new PutObjectResponse { ETag = ETagOf(request.Key), HttpStatusCode = HttpStatusCode.OK });
    }

    public override Task<DeleteObjectResponse> DeleteObjectAsync(DeleteObjectRequest request, CancellationToken cancellationToken = default)
    {
        Begin("DeleteObject", request, cancellationToken);
        lock (_lock) _objects.Remove(request.Key);
        return Task.FromResult(new DeleteObjectResponse { HttpStatusCode = HttpStatusCode.NoContent });
    }

    public override Task<DeleteObjectsResponse> DeleteObjectsAsync(DeleteObjectsRequest request, CancellationToken cancellationToken = default)
    {
        Begin("DeleteObjects", request, cancellationToken);
        if (request.Objects.Count > 1000)
            throw Error(HttpStatusCode.BadRequest, "MalformedXML");
        lock (_lock)
        {
            foreach (var item in request.Objects)
                _objects.Remove(item.Key);
        }
        return Task.FromResult(new DeleteObjectsResponse { HttpStatusCode = HttpStatusCode.OK });
    }

    public override Task<ListObjectsV2Response> ListObjectsV2Async(ListObjectsV2Request request, CancellationToken cancellationToken = default)
    {
        Begin("ListObjectsV2", request, cancellationToken);
        var prefix = request.Prefix ?? "";
        var maxKeys = Math.Min(request.MaxKeys ?? 1000, PageSize);
        var objects = new List<S3Object>();
        var prefixes = new List<string>();
        string? last = null;
        var truncated = false;
        lock (_lock)
        {
            foreach (var (key, stored) in _objects)
            {
                if (!key.StartsWith(prefix, StringComparison.Ordinal))
                    continue;
                var entry = key;
                var isCommonPrefix = false;
                if (!string.IsNullOrEmpty(request.Delimiter))
                {
                    var index = key.IndexOf(request.Delimiter, prefix.Length, StringComparison.Ordinal);
                    if (index >= 0)
                    {
                        entry = key.Substring(0, index + request.Delimiter.Length);
                        isCommonPrefix = true;
                    }
                }
                if (request.ContinuationToken != null && string.CompareOrdinal(entry, request.ContinuationToken) <= 0)
                    continue;
                if (entry == last)
                    continue; // one common prefix for all its keys
                if (objects.Count + prefixes.Count == maxKeys)
                {
                    truncated = true;
                    break;
                }
                if (!isCommonPrefix)
                    objects.Add(new S3Object { Key = key, Size = stored.Data.Length, ETag = stored.ETag, LastModified = stored.LastModified });
                else
                    prefixes.Add(entry);
                last = entry;
            }
        }
        return Task.FromResult(new ListObjectsV2Response
        {
            // S3 and the SDK give null, not an empty list, for an empty part of the response.
            S3Objects = objects.Count == 0 ? null : objects,
            CommonPrefixes = prefixes.Count == 0 ? null : prefixes,
            IsTruncated = truncated,
            NextContinuationToken = truncated ? last : null,
            HttpStatusCode = HttpStatusCode.OK,
        });
    }

    public override Task<CopyObjectResponse> CopyObjectAsync(CopyObjectRequest request, CancellationToken cancellationToken = default)
    {
        Begin("CopyObject", request, cancellationToken);
        lock (_lock)
        {
            if (!_objects.TryGetValue(request.SourceKey, out var stored))
                throw Error(HttpStatusCode.NotFound, "NoSuchKey");
            if (request.ETagToMatch != null && request.ETagToMatch != stored.ETag)
                throw Error(HttpStatusCode.PreconditionFailed, "PreconditionFailed");
            _objects[request.DestinationKey] = stored with { LastModified = DateTime.UtcNow };
        }
        return Task.FromResult(new CopyObjectResponse { HttpStatusCode = HttpStatusCode.OK });
    }

    public override Task<InitiateMultipartUploadResponse> InitiateMultipartUploadAsync(InitiateMultipartUploadRequest request, CancellationToken cancellationToken = default)
    {
        Begin("InitiateMultipartUpload", request, cancellationToken);
        var id = Guid.NewGuid().ToString("N");
        lock (_lock) _uploads[id] = new SortedDictionary<int, byte[]>();
        return Task.FromResult(new InitiateMultipartUploadResponse { UploadId = id, HttpStatusCode = HttpStatusCode.OK });
    }

    public override async Task<UploadPartResponse> UploadPartAsync(UploadPartRequest request, CancellationToken cancellationToken = default)
    {
        Begin("UploadPart", request, cancellationToken);
        await Task.Yield(); // a part is sent in the background, like a real request
        var data = ReadAll(request.InputStream);
        lock (_lock)
        {
            if (!_uploads.TryGetValue(request.UploadId, out var parts))
                throw Error(HttpStatusCode.NotFound, "NoSuchUpload");
            parts[request.PartNumber!.Value] = data;
        }
        return new UploadPartResponse { ETag = Quote(Md5Hex(data)), PartNumber = request.PartNumber, HttpStatusCode = HttpStatusCode.OK };
    }

    public override Task<CopyPartResponse> CopyPartAsync(CopyPartRequest request, CancellationToken cancellationToken = default)
    {
        Begin("CopyPart", request, cancellationToken);
        lock (_lock)
        {
            if (!_objects.TryGetValue(request.SourceKey, out var stored))
                throw Error(HttpStatusCode.NotFound, "NoSuchKey");
            if (request.ETagToMatch is { Count: > 0 } etags && !etags.Contains(stored.ETag))
                throw Error(HttpStatusCode.PreconditionFailed, "PreconditionFailed");
            if (!_uploads.TryGetValue(request.UploadId, out var parts))
                throw Error(HttpStatusCode.NotFound, "NoSuchUpload");
            var first = (int)(request.FirstByte ?? 0);
            var last = (int)(request.LastByte ?? stored.Data.Length - 1);
            var data = stored.Data.AsSpan(first, last - first + 1).ToArray();
            parts[request.PartNumber!.Value] = data;
            return Task.FromResult(new CopyPartResponse { ETag = Quote(Md5Hex(data)), PartNumber = request.PartNumber, HttpStatusCode = HttpStatusCode.OK });
        }
    }

    public override Task<CompleteMultipartUploadResponse> CompleteMultipartUploadAsync(CompleteMultipartUploadRequest request, CancellationToken cancellationToken = default)
    {
        Begin("CompleteMultipartUpload", request, cancellationToken);
        lock (_lock)
        {
            if (!_uploads.TryGetValue(request.UploadId, out var parts))
                throw Error(HttpStatusCode.NotFound, "NoSuchUpload");
            using var content = new MemoryStream();
            using var md5s = new MemoryStream();
            var previous = 0;
            foreach (var part in request.PartETags)
            {
                if (part.PartNumber <= previous || !parts.TryGetValue(part.PartNumber!.Value, out var data) || Quote(Md5Hex(data)) != part.ETag)
                    throw Error(HttpStatusCode.BadRequest, "InvalidPart");
                previous = part.PartNumber.Value;
                content.Write(data);
                md5s.Write(MD5.HashData(data));
            }
            var etag = Quote($"{Convert.ToHexStringLower(MD5.HashData(md5s.ToArray()))}-{request.PartETags.Count}");
            _objects[request.Key] = new StoredObject(content.ToArray(), etag, DateTime.UtcNow);
            _uploads.Remove(request.UploadId);
            return Task.FromResult(new CompleteMultipartUploadResponse { ETag = etag, HttpStatusCode = HttpStatusCode.OK });
        }
    }

    public override Task<AbortMultipartUploadResponse> AbortMultipartUploadAsync(AbortMultipartUploadRequest request, CancellationToken cancellationToken = default)
    {
        Begin("AbortMultipartUpload", request, cancellationToken);
        lock (_lock) _uploads.Remove(request.UploadId);
        return Task.FromResult(new AbortMultipartUploadResponse { HttpStatusCode = HttpStatusCode.NoContent });
    }

    private void Begin(string operation, AmazonWebServiceRequest request, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Calls.AddOrUpdate(operation, 1, (_, count) => count + 1);
        Requests.Enqueue(request);
        if (Fail?.Invoke(operation, request) is { } error)
            throw error;
    }

    private static byte[] ReadAll(Stream stream)
    {
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    private static string Md5Hex(byte[] data) => Convert.ToHexStringLower(MD5.HashData(data));

    private static string Quote(string value) => "\"" + value + "\"";

    private sealed record StoredObject(byte[] Data, string ETag, DateTime LastModified);
}
