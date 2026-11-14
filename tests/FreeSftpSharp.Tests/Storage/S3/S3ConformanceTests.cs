using SshServer.Filesystem.S3;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage.S3;

/// <summary>
/// The capabilities that <see cref="S3FileSystem"/> must declare. A fixed value on purpose: S3 keys are case-sensitive on
/// every operating system, so <see cref="StorageCapabilities.CaseInsensitivePaths"/> is never set.
/// </summary>
internal static class S3Expected
{
    public const StorageCapabilities Capabilities = StorageCapabilities.Append | StorageCapabilities.Rename | StorageCapabilities.ServerSideCopy;
}

/// <summary>
/// The conformance suite for <see cref="S3FileSystem"/> on <see cref="FakeS3Client"/>, below a key prefix. Runs
/// everywhere; <see cref="MinioS3ConformanceTests"/> runs the same suite against a real S3 server.
/// </summary>
public sealed class FakeS3ConformanceTests : FileSystemConformanceTests<FakeS3ConformanceTests.Fixture>
{
    public sealed class Fixture : IFileSystemFixture
    {
        public IFileSystem FileSystem { get; } = new S3FileSystem(new FakeS3Client(), new S3StorageOptions { Bucket = "bucket", KeyPrefix = "users/test" });
        public StorageCapabilities ExpectedCapabilities => S3Expected.Capabilities;
        public void Dispose() { }
    }
}

/// <summary>
/// The conformance suite for <see cref="S3FileSystem"/> against a real S3 server (MinIO in CI), each test below its own
/// key prefix. Skipped unless FREESFTPSHARP_TEST_S3_ENDPOINT is set (see <see cref="S3TestServer"/>).
/// </summary>
[Trait("Category", "S3")]
public sealed class MinioS3ConformanceTests : FileSystemConformanceTests<MinioS3ConformanceTests.Fixture>
{
    public sealed class Fixture : IFileSystemFixture
    {
        private readonly string _prefix = "conformance/" + Guid.NewGuid().ToString("N");

        public Fixture()
        {
            S3TestServer.SkipIfUnavailable();
            FileSystem = new S3FileSystem(S3TestServer.Client, S3TestServer.Options(_prefix));
        }

        public IFileSystem FileSystem { get; }
        public StorageCapabilities ExpectedCapabilities => S3Expected.Capabilities;
        public void Dispose() => S3TestServer.DeletePrefix(_prefix);
    }
}
