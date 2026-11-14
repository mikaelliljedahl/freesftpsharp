using System.Collections.Concurrent;
using Google.Apis.Auth.OAuth2;
using Google.Cloud.Storage.V1;

namespace SshServer.Filesystem.Gcs;

/// <summary>The settings that make one storage client: the same settings share one client (and its connections).</summary>
internal sealed record GcsClientSettings(string? Endpoint, string? CredentialsJson, string? CredentialsFile)
{
    public static GcsClientSettings From(GcsStorageOptions options)
        => new(NullIfEmpty(options.Endpoint), NullIfEmpty(options.CredentialsJson), NullIfEmpty(options.CredentialsFile));

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    public override string ToString() => $"GcsClientSettings {{ Endpoint = {Endpoint}, CredentialsJson = {(CredentialsJson == null ? "" : "***")}, CredentialsFile = {CredentialsFile} }}";
}

/// <summary>
/// The storage clients of the provider, one per <see cref="GcsClientSettings"/>, created at the first use and disposed with
/// the service provider. A client is thread safe, so all sessions with the same settings share it.
/// </summary>
public sealed class GcsClientCache : IDisposable
{
    private readonly ConcurrentDictionary<GcsClientSettings, Lazy<StorageClient>> _clients = new();
    private readonly Func<GcsClientSettings, StorageClient> _create;

    public GcsClientCache()
        : this(CreateClient)
    {
    }

    internal GcsClientCache(Func<GcsClientSettings, StorageClient> create)
    {
        _create = create;
    }

    /// <summary>The client for the endpoint and credentials of <paramref name="options"/>.</summary>
    public StorageClient Get(GcsStorageOptions options)
    {
        var settings = GcsClientSettings.From(options);
        return _clients.GetOrAdd(settings, s => new Lazy<StorageClient>(() => _create(s))).Value;
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

    private static StorageClient CreateClient(GcsClientSettings settings)
    {
        var builder = new StorageClientBuilder();
        // Only service account keys: the Google client rejects the other credential types of a key file as a security risk.
        if (settings.CredentialsJson != null)
            builder.GoogleCredential = CredentialFactory.FromJson<ServiceAccountCredential>(settings.CredentialsJson).ToGoogleCredential();
        else if (settings.CredentialsFile != null)
            builder.GoogleCredential = CredentialFactory.FromFile<ServiceAccountCredential>(settings.CredentialsFile).ToGoogleCredential();
        if (settings.Endpoint != null)
        {
            builder.BaseUri = settings.Endpoint.TrimEnd('/') + "/storage/v1/";
            // An emulator needs no login; with credentials the requests are still signed.
            builder.UnauthenticatedAccess = settings.CredentialsJson == null && settings.CredentialsFile == null;
        }
        // Without credentials the client takes the Application Default Credentials.
        return builder.Build();
    }
}
