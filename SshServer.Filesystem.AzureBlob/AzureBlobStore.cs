using System.Text;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;

namespace SshServer.Filesystem.AzureBlob;

/// <summary>The size, write time and ETag of a blob (properties or a listing); <see cref="IsFolder"/> for a directory marker.</summary>
internal sealed record BlobInfo(long Size, DateTime LastModifiedUtc, ETag ETag, bool IsFolder = false);

/// <summary>
/// The Azure requests of one storage location: the only class that builds SDK requests, so the container, the access
/// tier and the marker metadata are set in one place. It throws the SDK exceptions; the callers translate them with
/// <see cref="AzureBlobErrors"/> and the virtual path.
/// </summary>
internal sealed class AzureBlobStore
{
    /// <summary>The metadata that marks a blob as a directory (the convention of Storage Explorer and Data Lake).</summary>
    public const string FolderMetadata = "hdi_isfolder";

    /// <summary>The most blocks of one blob.</summary>
    public const int MaxBlocks = 50_000;

    private readonly BlobContainerClient _container;

    public AzureBlobStore(BlobContainerClient container, AzureBlobStorageOptions options)
    {
        _container = container;
        Options = options;
    }

    public AzureBlobStorageOptions Options { get; }

    private AccessTier? Tier => string.IsNullOrEmpty(Options.AccessTier) ? default(AccessTier?) : new AccessTier(Options.AccessTier);

    /// <summary>The blob, or null when it does not exist.</summary>
    public async Task<BlobInfo?> HeadAsync(string name, CancellationToken ct)
    {
        try
        {
            var response = await _container.GetBlobClient(name).GetPropertiesAsync(cancellationToken: ct).ConfigureAwait(false);
            return new BlobInfo(response.Value.ContentLength, response.Value.LastModified.UtcDateTime, response.Value.ETag, IsFolder(response.Value.Metadata));
        }
        catch (RequestFailedException ex) when (AzureBlobErrors.IsNotFound(ex))
        {
            return null;
        }
    }

    /// <summary>The first blobs whose names start with <paramref name="prefix"/>, in name order (one request, no delimiter).</summary>
    public async Task<IReadOnlyList<BlobItem>> FirstBlobsAsync(string prefix, int count, CancellationToken ct)
    {
        await foreach (var page in _container.GetBlobsAsync(BlobTraits.None, BlobStates.None, prefix: prefix, cancellationToken: ct).AsPages(pageSizeHint: count).ConfigureAwait(false))
            return page.Values.Take(count).ToList();
        return [];
    }

    /// <summary>The blobs and the blob prefixes directly below <paramref name="prefix"/> (delimiter "/"), all pages.</summary>
    public AsyncPageable<BlobHierarchyItem> ListHierarchy(string prefix, CancellationToken ct)
        => _container.GetBlobsByHierarchyAsync(BlobTraits.Metadata, BlobStates.None, delimiter: "/", prefix: prefix, cancellationToken: ct);

    /// <summary>Every blob whose name starts with <paramref name="prefix"/>, all pages.</summary>
    public AsyncPageable<BlobItem> ListAll(string prefix, CancellationToken ct)
        => _container.GetBlobsAsync(BlobTraits.None, BlobStates.None, prefix: prefix, cancellationToken: ct);

    /// <summary>Stores a blob in one request (replaces an existing one); a directory marker has the folder metadata.</summary>
    public async Task PutAsync(string name, byte[] data, int count, bool folderMarker, CancellationToken ct)
    {
        using var stream = new MemoryStream(data, 0, count, writable: false);
        await _container.GetBlobClient(name).UploadAsync(stream, new BlobUploadOptions
        {
            AccessTier = Tier,
            Metadata = folderMarker ? new Dictionary<string, string> { [FolderMetadata] = "true" } : null,
        }, ct).ConfigureAwait(false);
    }

    public async Task DeleteAsync(string name, CancellationToken ct)
        => await _container.GetBlobClient(name).DeleteIfExistsAsync(DeleteSnapshotsOption.IncludeSnapshots, cancellationToken: ct).ConfigureAwait(false);

    /// <summary>Copies a blob on the server (the properties and the metadata come along) and waits until the copy is done.</summary>
    public async Task CopyAsync(string sourceName, string targetName, BlobInfo source, CancellationToken ct)
    {
        var sourceClient = _container.GetBlobClient(sourceName);
        var operation = await _container.GetBlobClient(targetName).StartCopyFromUriAsync(sourceClient.Uri, new BlobCopyFromUriOptions
        {
            AccessTier = Tier,
            SourceConditions = new BlobRequestConditions { IfMatch = source.ETag },
        }, ct).ConfigureAwait(false);
        await operation.WaitForCompletionAsync(ct).ConfigureAwait(false);
    }

    /// <summary>The ids and sizes of the committed blocks, in order; empty for a blob that was stored in one request.</summary>
    public async Task<IReadOnlyList<BlobBlock>> CommittedBlocksAsync(string name, CancellationToken ct)
    {
        var response = await _container.GetBlockBlobClient(name).GetBlockListAsync(BlockListTypes.Committed, cancellationToken: ct).ConfigureAwait(false);
        return response.Value.CommittedBlocks.ToList();
    }

    /// <summary>Stages one block; it is not part of the blob until <see cref="CommitAsync"/>.</summary>
    public async Task StageBlockAsync(string name, string blockId, byte[] data, int count, CancellationToken ct)
    {
        using var stream = new MemoryStream(data, 0, count, writable: false);
        await _container.GetBlockBlobClient(name).StageBlockAsync(blockId, stream, cancellationToken: ct).ConfigureAwait(false);
    }

    /// <summary>Makes the blob of the staged and committed blocks, in this order; replaces an existing blob.</summary>
    public async Task CommitAsync(string name, IEnumerable<string> blockIds, ETag? ifMatch, CancellationToken ct)
    {
        await _container.GetBlockBlobClient(name).CommitBlockListAsync(blockIds, new CommitBlockListOptions
        {
            AccessTier = Tier,
            Conditions = ifMatch is { } etag ? new BlobRequestConditions { IfMatch = etag } : null,
        }, ct).ConfigureAwait(false);
    }

    /// <summary>Reads exactly <paramref name="destination"/>.Length bytes at <paramref name="offset"/> of the blob with this ETag.</summary>
    public async Task ReadRangeAsync(string name, ETag eTag, long offset, Memory<byte> destination, CancellationToken ct)
    {
        var response = await _container.GetBlobClient(name).DownloadStreamingAsync(new BlobDownloadOptions
        {
            Range = new HttpRange(offset, destination.Length),
            Conditions = new BlobRequestConditions { IfMatch = eTag },
        }, ct).ConfigureAwait(false);
        using var content = response.Value.Content;
        await content.ReadExactlyAsync(destination, ct).ConfigureAwait(false);
    }

    /// <summary>The id of block number <paramref name="number"/> of the upload with this nonce. All ids of a blob have the same length.</summary>
    public static string BlockId(string nonce, int number)
        => Convert.ToBase64String(Encoding.ASCII.GetBytes($"{nonce}{number:D8}"));

    /// <summary>The length of every id that <see cref="BlockId"/> makes.</summary>
    public static int BlockIdLength { get; } = BlockId("00000000", 0).Length;

    /// <summary>True for the metadata of a directory marker.</summary>
    public static bool IsFolder(IDictionary<string, string>? metadata)
        => metadata != null && metadata.TryGetValue(FolderMetadata, out var value) && string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);

    public static DateTime ToUtc(DateTimeOffset? time) => time?.UtcDateTime ?? DateTime.UnixEpoch;
}
