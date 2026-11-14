using SshServer.Filesystem.Encrypted;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage.Encrypted;

/// <summary>
/// The conformance suite for <see cref="EncryptedFileSystem"/> on <see cref="LocalFileSystem"/> in a new temporary
/// directory. The format writes a file only once, from the start to the end, so the backend declares no
/// <see cref="StorageCapabilities.RandomAccessWrite"/> (writes at other offsets, size changes) and no
/// <see cref="StorageCapabilities.Append"/>; the suite checks that these throw OpNotSupported.
/// </summary>
public sealed class EncryptedFileSystemConformanceTests : FileSystemConformanceTests<EncryptedFileSystemConformanceTests.Fixture>
{
    public sealed class Fixture : IFileSystemFixture
    {
        private readonly string _tempDirectory = Path.Combine(Path.GetTempPath(), "freesftpsharp-tests", Guid.NewGuid().ToString("N"));

        public Fixture()
        {
            var root = Path.Combine(_tempDirectory, "root");
            Directory.CreateDirectory(root);
            FileSystem = new EncryptedFileSystem(new LocalFileSystem(root), TestKeys.Provider("a", ("a", TestKeys.KeyA)));
        }

        public IFileSystem FileSystem { get; }

        public StorageCapabilities ExpectedCapabilities => StorageCapabilities.Rename | StorageCapabilities.SetTimes | StorageCapabilities.SetPermissions;

        public void Dispose()
        {
            try { Directory.Delete(_tempDirectory, recursive: true); } catch { }
        }
    }
}
