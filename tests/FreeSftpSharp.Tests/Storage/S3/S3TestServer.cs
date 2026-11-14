using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Util;
using SshServer.Filesystem.S3;

namespace FreeSftpSharp.Tests.Storage.S3;

/// <summary>
/// The real S3 server of the S3 tests (MinIO in CI): FREESFTPSHARP_TEST_S3_ENDPOINT (for example
/// http://127.0.0.1:19000), and optionally FREESFTPSHARP_TEST_S3_ACCESS_KEY, FREESFTPSHARP_TEST_S3_SECRET_KEY (default
/// minioadmin, the MinIO default) and FREESFTPSHARP_TEST_S3_BUCKET (default freesftpsharp-tests, created when missing).
/// Without the endpoint the tests are skipped.
/// </summary>
internal static class S3TestServer
{
    public const string EndpointVariable = "FREESFTPSHARP_TEST_S3_ENDPOINT";

    private static readonly Lazy<IAmazonS3> LazyClient = new(CreateClientAndBucket);

    public static string? Endpoint => NullIfEmpty(Environment.GetEnvironmentVariable(EndpointVariable));

    public static string Bucket => NullIfEmpty(Environment.GetEnvironmentVariable("FREESFTPSHARP_TEST_S3_BUCKET")) ?? "freesftpsharp-tests";

    public static void SkipIfUnavailable()
    {
        if (Endpoint == null)
            Assert.Skip($"{EndpointVariable} is not set (an S3 server such as MinIO is needed).");
    }

    /// <summary>The options of a user root below <paramref name="keyPrefix"/>, with the credentials of the test server.</summary>
    public static S3StorageOptions Options(string keyPrefix) => new()
    {
        Bucket = Bucket,
        KeyPrefix = keyPrefix,
        Endpoint = Endpoint,
        ForcePathStyle = true,
        Region = "us-east-1",
        AccessKey = NullIfEmpty(Environment.GetEnvironmentVariable("FREESFTPSHARP_TEST_S3_ACCESS_KEY")) ?? "minioadmin",
        SecretKey = NullIfEmpty(Environment.GetEnvironmentVariable("FREESFTPSHARP_TEST_S3_SECRET_KEY")) ?? "minioadmin",
    };

    /// <summary>A client of the test server; the bucket exists.</summary>
    public static IAmazonS3 Client => LazyClient.Value;

    /// <summary>
    /// Creates the bucket when it is missing (once per test run). A test that reaches the server through its own client
    /// (for example the SFTP server of <c>S3SftpServerFixture</c>) calls this first: on a new server (CI) the bucket
    /// does not exist until a test uses <see cref="Client"/>.
    /// </summary>
    public static void EnsureBucket() => _ = LazyClient.Value;

    /// <summary>Removes every object below a key prefix (cleanup; errors are ignored).</summary>
    public static void DeletePrefix(string keyPrefix)
    {
        try
        {
            var prefix = keyPrefix.TrimEnd('/') + "/";
            string? token = null;
            do
            {
                var page = Client.ListObjectsV2Async(new ListObjectsV2Request { BucketName = Bucket, Prefix = prefix, ContinuationToken = token }).GetAwaiter().GetResult();
                var keys = (page.S3Objects ?? []).Select(o => new KeyVersion { Key = o.Key }).ToList();
                if (keys.Count > 0)
                    Client.DeleteObjectsAsync(new DeleteObjectsRequest { BucketName = Bucket, Objects = keys }).GetAwaiter().GetResult();
                token = page.IsTruncated == true ? page.NextContinuationToken : null;
            }
            while (token != null);
        }
        catch (Exception)
        {
            // Cleanup must not fail a test.
        }
    }

    /// <summary>
    /// The multipart uploads of one object key that were neither completed nor aborted. MinIO lists the uploads only
    /// of an exact key, not of a directory prefix.
    /// </summary>
    public static async Task<int> CountOpenUploadsAsync(string key)
    {
        var response = await Client.ListMultipartUploadsAsync(new ListMultipartUploadsRequest { BucketName = Bucket, Prefix = key });
        return response.MultipartUploads?.Count ?? 0;
    }

    private static IAmazonS3 CreateClientAndBucket()
    {
        var client = new S3ClientCache().Get(Options("unused"));
        if (!AmazonS3Util.DoesS3BucketExistV2Async(client, Bucket).GetAwaiter().GetResult())
            client.PutBucketAsync(new PutBucketRequest { BucketName = Bucket }).GetAwaiter().GetResult();
        return client;
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
