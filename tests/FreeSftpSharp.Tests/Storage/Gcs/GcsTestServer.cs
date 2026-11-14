using Google;
using Google.Cloud.Storage.V1;
using SshServer.Filesystem.Gcs;

namespace FreeSftpSharp.Tests.Storage.Gcs;

/// <summary>
/// The Cloud Storage emulator of the GCS tests (fake-gcs-server in CI): FREESFTPSHARP_TEST_GCS_ENDPOINT (for example
/// http://127.0.0.1:4443; the server is started with <c>-scheme http -external-url THAT_URL</c>), and optionally
/// FREESFTPSHARP_TEST_GCS_BUCKET (default freesftpsharp-tests, created when missing). Without the endpoint the tests are skipped.
/// </summary>
internal static class GcsTestServer
{
    public const string EndpointVariable = "FREESFTPSHARP_TEST_GCS_ENDPOINT";

    private static readonly Lazy<StorageClient> LazyClient = new(CreateClientAndBucket);

    public static string? Endpoint => NullIfEmpty(Environment.GetEnvironmentVariable(EndpointVariable));

    public static string Bucket => NullIfEmpty(Environment.GetEnvironmentVariable("FREESFTPSHARP_TEST_GCS_BUCKET")) ?? "freesftpsharp-tests";

    public static void SkipIfUnavailable()
    {
        if (Endpoint == null)
            Assert.Skip($"{EndpointVariable} is not set (a Cloud Storage emulator such as fake-gcs-server is needed).");
    }

    /// <summary>The options of a user root below <paramref name="keyPrefix"/>, for the emulator (no credentials).</summary>
    public static GcsStorageOptions Options(string keyPrefix) => new()
    {
        Bucket = Bucket,
        KeyPrefix = keyPrefix,
        Endpoint = Endpoint,
    };

    /// <summary>A client of the emulator; the bucket exists.</summary>
    public static StorageClient Client => LazyClient.Value;

    /// <summary>
    /// Creates the bucket when it is missing (once per test run). A test that reaches the emulator through its own
    /// client (for example the SFTP server of <c>GcsSftpServerFixture</c>) calls this first.
    /// </summary>
    public static void EnsureBucket() => _ = LazyClient.Value;

    /// <summary>Removes every object below a key prefix (cleanup; errors are ignored).</summary>
    public static void DeletePrefix(string keyPrefix)
    {
        try
        {
            foreach (var item in Client.ListObjects(Bucket, keyPrefix.TrimEnd('/') + "/").ToList())
                Client.DeleteObject(Bucket, item.Name);
        }
        catch (Exception)
        {
            // Cleanup must not fail a test.
        }
    }

    /// <summary>The names of the objects below a key prefix, in name order.</summary>
    public static List<string> ObjectNames(string keyPrefix)
        => Client.ListObjects(Bucket, keyPrefix.TrimEnd('/') + "/").Select(o => o.Name).ToList();

    private static StorageClient CreateClientAndBucket()
    {
        var client = new GcsClientCache().Get(Options("unused"));
        try
        {
            client.GetBucket(Bucket);
        }
        catch (GoogleApiException ex) when (ex.HttpStatusCode == System.Net.HttpStatusCode.NotFound)
        {
            client.CreateBucket("freesftpsharp-tests-project", Bucket);
        }
        return client;
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
