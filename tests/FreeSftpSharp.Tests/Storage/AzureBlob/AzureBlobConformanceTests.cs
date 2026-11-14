using SshServer.Filesystem.AzureBlob;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage.AzureBlob;

/// <summary>
/// The capabilities that <see cref="AzureBlobFileSystem"/> must declare. A fixed value on purpose: blob names are
/// case-sensitive on every operating system, so <see cref="StorageCapabilities.CaseInsensitivePaths"/> is never set.
/// </summary>
internal static class AzureBlobExpected
{
    public const StorageCapabilities Capabilities = StorageCapabilities.Append | StorageCapabilities.Rename | StorageCapabilities.ServerSideCopy;
}

/// <summary>
/// The conformance suite for <see cref="AzureBlobFileSystem"/> against a real Azure Blob server (Azurite in CI), each
/// test below its own name prefix. Skipped unless FREESFTPSHARP_TEST_AZURITE is set (see <see cref="AzuriteTestServer"/>).
/// </summary>
[Trait("Category", "Azure")]
public sealed class AzuriteConformanceTests : FileSystemConformanceTests<AzuriteConformanceTests.Fixture>
{
    public sealed class Fixture : IFileSystemFixture
    {
        private readonly string _prefix = "conformance/" + Guid.NewGuid().ToString("N");

        public Fixture()
        {
            AzuriteTestServer.SkipIfUnavailable();
            FileSystem = new AzureBlobFileSystem(AzuriteTestServer.Client, AzuriteTestServer.Options(_prefix));
        }

        public IFileSystem FileSystem { get; }
        public StorageCapabilities ExpectedCapabilities => AzureBlobExpected.Capabilities;
        public void Dispose() => AzuriteTestServer.DeletePrefix(_prefix);
    }
}
