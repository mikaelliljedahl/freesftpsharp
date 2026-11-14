using SshServer.Filesystem.Gcs;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage.Gcs;

/// <summary>
/// The capabilities that <see cref="GcsFileSystem"/> must declare. A fixed value on purpose: object names are
/// case-sensitive on every operating system, so <see cref="StorageCapabilities.CaseInsensitivePaths"/> is never set.
/// </summary>
internal static class GcsExpected
{
    public const StorageCapabilities Capabilities = StorageCapabilities.Append | StorageCapabilities.Rename | StorageCapabilities.ServerSideCopy;
}

/// <summary>
/// The conformance suite for <see cref="GcsFileSystem"/> against a Cloud Storage emulator (fake-gcs-server in CI), each
/// test below its own key prefix. Skipped unless FREESFTPSHARP_TEST_GCS_ENDPOINT is set (see <see cref="GcsTestServer"/>).
/// </summary>
[Trait("Category", "Gcs")]
public sealed class EmulatorGcsConformanceTests : FileSystemConformanceTests<EmulatorGcsConformanceTests.Fixture>
{
    public sealed class Fixture : IFileSystemFixture
    {
        private readonly string _prefix = "conformance/" + Guid.NewGuid().ToString("N");

        public Fixture()
        {
            GcsTestServer.SkipIfUnavailable();
            FileSystem = new GcsFileSystem(GcsTestServer.Client, GcsTestServer.Options(_prefix));
        }

        public IFileSystem FileSystem { get; }
        public StorageCapabilities ExpectedCapabilities => GcsExpected.Capabilities;
        public void Dispose() => GcsTestServer.DeletePrefix(_prefix);
    }
}
