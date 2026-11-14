using System.Collections.Concurrent;
using Amazon;
using Amazon.Runtime;
using Amazon.S3;

namespace SshServer.Filesystem.S3;

/// <summary>The settings that make one S3 client: the same settings share one client (and its connections).</summary>
internal sealed record S3ClientSettings(string? Endpoint, string? Region, bool ForcePathStyle, string? AccessKey, string? SecretKey)
{
    public static S3ClientSettings From(S3StorageOptions options) => new(
        NullIfEmpty(options.Endpoint), NullIfEmpty(options.Region), options.ForcePathStyle, NullIfEmpty(options.AccessKey), NullIfEmpty(options.SecretKey));

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    public override string ToString() => $"S3ClientSettings {{ Endpoint = {Endpoint}, Region = {Region}, AccessKey = {AccessKey} }}";
}

/// <summary>
/// The S3 clients of the storage provider, one per <see cref="S3ClientSettings"/>, created at the first use and disposed
/// with the service provider. A client is thread safe, so all sessions with the same settings share it.
/// </summary>
public sealed class S3ClientCache : IDisposable
{
    private readonly ConcurrentDictionary<S3ClientSettings, Lazy<IAmazonS3>> _clients = new();
    private readonly Func<S3ClientSettings, IAmazonS3> _create;

    public S3ClientCache()
        : this(CreateClient)
    {
    }

    internal S3ClientCache(Func<S3ClientSettings, IAmazonS3> create)
    {
        _create = create;
    }

    /// <summary>The client for the endpoint, region and credentials of <paramref name="options"/>.</summary>
    public IAmazonS3 Get(S3StorageOptions options)
    {
        var settings = S3ClientSettings.From(options);
        return _clients.GetOrAdd(settings, s => new Lazy<IAmazonS3>(() => _create(s))).Value;
    }

    public void Dispose()
    {
        foreach (var client in _clients.Values)
        {
            if (client.IsValueCreated)
                client.Value.Dispose();
        }
        _clients.Clear();
    }

    private static IAmazonS3 CreateClient(S3ClientSettings settings)
    {
        var config = new AmazonS3Config
        {
            ForcePathStyle = settings.ForcePathStyle,
            // Only the checksums that S3 requires: many S3-compatible stores reject the default trailing CRC checksums.
            // TLS protects the data on the way.
            RequestChecksumCalculation = RequestChecksumCalculation.WHEN_REQUIRED,
            ResponseChecksumValidation = ResponseChecksumValidation.WHEN_REQUIRED,
        };
        if (settings.Endpoint != null)
        {
            config.ServiceURL = settings.Endpoint;
            config.AuthenticationRegion = settings.Region ?? "us-east-1";
        }
        else if (settings.Region != null)
        {
            config.RegionEndpoint = RegionEndpoint.GetBySystemName(settings.Region);
        }

        // Without keys the SDK takes the credentials of the environment: variables, profile, instance role, IRSA.
        return settings.AccessKey != null
            ? new AmazonS3Client(new BasicAWSCredentials(settings.AccessKey, settings.SecretKey), config)
            : new AmazonS3Client(config);
    }
}
