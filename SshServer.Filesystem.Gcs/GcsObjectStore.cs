using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Google;
using Google.Apis.Storage.v1;
using Google.Apis.Storage.v1.Data;
using Google.Cloud.Storage.V1;
using GcsObject = Google.Apis.Storage.v1.Data.Object;

namespace SshServer.Filesystem.Gcs;

/// <summary>The size, write time and generation of an object (an object metadata request or a listing).</summary>
internal sealed record GcsObjectInfo(long Size, DateTime LastModifiedUtc, long Generation)
{
    public static GcsObjectInfo From(GcsObject item)
        => new((long)(item.Size ?? 0), GcsObjectStore.ToUtc(item.UpdatedRaw), item.Generation ?? 0);
}

/// <summary>
/// The Cloud Storage requests of one storage location: the only class that builds requests, so the bucket and the
/// storage class are set in one place. It throws the exceptions of the Google client (and <see cref="HttpRequestException"/>
/// with the status for the resumable upload); the callers translate them with <see cref="GcsErrors"/> and the virtual path.
/// </summary>
internal sealed class GcsObjectStore
{
    private const string OctetStream = "application/octet-stream";

    private readonly StorageClient _client;
    private readonly Uri _uploadBase;

    public GcsObjectStore(StorageClient client, GcsStorageOptions options)
    {
        _client = client;
        Options = options;
        // The upload endpoint of the same server as the API endpoint (Google or an emulator).
        _uploadBase = new Uri(client.Service.BaseUri.Replace("/storage/v1/", "/upload/storage/v1/", StringComparison.Ordinal));
    }

    public GcsStorageOptions Options { get; }

    private string Bucket => Options.Bucket;

    /// <summary>The object, or null when it does not exist.</summary>
    public async Task<GcsObjectInfo?> HeadAsync(string key, CancellationToken ct)
    {
        try
        {
            return GcsObjectInfo.From(await _client.GetObjectAsync(Bucket, key, cancellationToken: ct).ConfigureAwait(false));
        }
        catch (GoogleApiException ex) when (GcsErrors.IsNotFound(ex))
        {
            return null;
        }
    }

    /// <summary>The first objects whose names start with <paramref name="prefix"/>, in name order (one page, no delimiter).</summary>
    public async Task<IReadOnlyList<GcsObject>> FirstObjectsAsync(string prefix, int maxKeys, CancellationToken ct)
    {
        await foreach (var page in ListPages(prefix, delimiter: null, maxKeys).WithCancellation(ct).ConfigureAwait(false))
            return (page.Items ?? []).Take(maxKeys).ToList();
        return [];
    }

    /// <summary>The pages of a listing: <see cref="Objects.Items"/> are the objects, <see cref="Objects.Prefixes"/> the directories.</summary>
    public IAsyncEnumerable<Objects> ListPages(string prefix, string? delimiter, int? pageSize)
        => _client.ListObjectsAsync(Bucket, prefix, new ListObjectsOptions { Delimiter = delimiter, PageSize = pageSize }).AsRawResponses();

    /// <summary>Every object whose name starts with <paramref name="prefix"/>, all pages.</summary>
    public async IAsyncEnumerable<GcsObject> ListAllAsync(string prefix, [EnumeratorCancellation] CancellationToken ct)
    {
        await foreach (var page in ListPages(prefix, delimiter: null, pageSize: null).WithCancellation(ct).ConfigureAwait(false))
        {
            foreach (var item in page.Items ?? [])
                yield return item;
        }
    }

    /// <summary>Stores a whole object in one request. <paramref name="createOnly"/>: fails with 412 when the object exists.</summary>
    public async Task PutAsync(string key, byte[] data, int count, bool createOnly, CancellationToken ct)
    {
        using var stream = new MemoryStream(data, 0, count, writable: false);
        await _client.UploadObjectAsync(NewObject(key), stream, new UploadObjectOptions { IfGenerationMatch = createOnly ? 0 : null }, ct).ConfigureAwait(false);
    }

    public Task DeleteAsync(string key, CancellationToken ct)
        => _client.DeleteObjectAsync(Bucket, key, cancellationToken: ct);

    /// <summary>Removes the objects, a few at a time (there is no batch request); an object that is gone already is no error.</summary>
    public async Task DeleteManyAsync(IReadOnlyList<string> keys, CancellationToken ct)
    {
        await Parallel.ForEachAsync(keys, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (key, token) =>
        {
            try
            {
                await DeleteAsync(key, token).ConfigureAwait(false);
            }
            catch (GoogleApiException ex) when (GcsErrors.IsNotFound(ex))
            {
            }
        }).ConfigureAwait(false);
    }

    /// <summary>Copies an object on the server (any size); the copy is of the generation that was seen.</summary>
    public Task CopyAsync(string sourceKey, string targetKey, GcsObjectInfo source, CancellationToken ct)
        => _client.CopyObjectAsync(Bucket, sourceKey, Bucket, targetKey, new CopyObjectOptions { SourceGeneration = source.Generation }, ct);

    /// <summary>
    /// Joins <paramref name="appended"/> to the end of <paramref name="existing"/> (compose, on the server): fails when
    /// <paramref name="key"/> was replaced since <paramref name="existing"/> was seen.
    /// </summary>
    public async Task ComposeAppendAsync(string key, GcsObjectInfo existing, string appended, CancellationToken ct)
    {
        var request = new ComposeRequest
        {
            Destination = NewObject(key),
            SourceObjects =
            [
                new ComposeRequest.SourceObjectsData { Name = key, Generation = existing.Generation },
                new ComposeRequest.SourceObjectsData { Name = appended },
            ],
        };
        var compose = _client.Service.Objects.Compose(request, Bucket, key);
        compose.IfGenerationMatch = existing.Generation;
        await compose.ExecuteAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Reads exactly <paramref name="length"/> bytes at <paramref name="offset"/> of this generation of the object.</summary>
    public async Task ReadRangeAsync(string key, long generation, long offset, byte[] destination, int length, CancellationToken ct)
    {
        using var stream = new MemoryStream(destination, 0, length, writable: true);
        await _client.DownloadObjectAsync(Bucket, key, stream, new DownloadObjectOptions
        {
            Generation = generation,
            Range = new RangeHeaderValue(offset, offset + length - 1),
            DownloadValidationMode = DownloadValidationMode.Never, // a range has no hash of its own
        }, ct).ConfigureAwait(false);
        if (stream.Position != length)
            throw new IOException($"The storage returned {stream.Position} of {length} bytes.");
    }

    /// <summary>Starts a resumable upload session; the result is the session URI.</summary>
    public async Task<Uri> InitiateUploadAsync(string key, bool createOnly, CancellationToken ct)
    {
        var url = new Uri(_uploadBase, $"b/{Uri.EscapeDataString(Bucket)}/o?uploadType=resumable&name={Uri.EscapeDataString(key)}" + (createOnly ? "&ifGenerationMatch=0" : ""));
        var metadata = JsonSerializer.Serialize(
            new { name = key, contentType = OctetStream, storageClass = string.IsNullOrEmpty(Options.StorageClass) ? null : Options.StorageClass },
            new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent(metadata, Encoding.UTF8, "application/json") };
        request.Headers.Add("X-Upload-Content-Type", OctetStream);
        using var response = await _client.Service.HttpClient.SendAsync(request, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw await FailureAsync(response, "start the upload", ct).ConfigureAwait(false);
        return response.Headers.Location ?? throw new HttpRequestException("The storage gave no upload session.");
    }

    /// <summary>
    /// Sends the bytes at <paramref name="offset"/> of a resumable upload. Without <paramref name="total"/> the chunk is
    /// not the last one (the size of a chunk is a multiple of 256 KiB); with it, the upload is finished and the object stored.
    /// </summary>
    public async Task SendChunkAsync(Uri session, ReadOnlyMemory<byte> data, long offset, long? total, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, session) { Content = new ReadOnlyMemoryContent(data) };
        request.Content.Headers.ContentRange = (data.Length, total) switch
        {
            (0, { } size) => new ContentRangeHeaderValue(size), // "bytes */size": no more data
            (_, { } size) => new ContentRangeHeaderValue(offset, offset + data.Length - 1, size),
            _ => new ContentRangeHeaderValue(offset, offset + data.Length - 1),
        };
        using var response = await _client.Service.HttpClient.SendAsync(request, ct).ConfigureAwait(false);
        // 308 "resume incomplete" answers a chunk that is not the last; 200 or 201 answers the last one.
        var expected = total == null ? response.StatusCode == (HttpStatusCode)308 : response.IsSuccessStatusCode;
        if (!expected)
            throw await FailureAsync(response, "send a chunk", ct).ConfigureAwait(false);
    }

    /// <summary>Cancels a resumable upload session. Never throws: the upload was abandoned already, and Cloud Storage discards a session that is not used for a week.</summary>
    public async Task CancelUploadAsync(Uri session)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Delete, session) { Content = new ByteArrayContent([]) };
            using var response = await _client.Service.HttpClient.SendAsync(request, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException or GoogleApiException)
        {
            // See above.
        }
    }

    /// <summary>The time of the raw RFC 3339 string of the API (the parsed properties of the client fail on some emulators).</summary>
    public static DateTime ToUtc(string? rfc3339)
        => DateTimeOffset.TryParse(rfc3339, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var time)
            ? time.UtcDateTime
            : DateTime.UnixEpoch;

    private GcsObject NewObject(string key) => new()
    {
        Bucket = Bucket,
        Name = key,
        ContentType = OctetStream,
        StorageClass = string.IsNullOrEmpty(Options.StorageClass) ? null : Options.StorageClass,
    };

    private static async Task<HttpRequestException> FailureAsync(HttpResponseMessage response, string action, CancellationToken ct)
    {
        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return new HttpRequestException($"The storage could not {action}: HTTP {(int)response.StatusCode} {Truncate(body)}", null, response.StatusCode);
    }

    private static string Truncate(string text) => text.Length <= 300 ? text : text.Substring(0, 300);
}
