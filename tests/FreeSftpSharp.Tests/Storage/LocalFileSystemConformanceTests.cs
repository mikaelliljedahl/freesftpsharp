using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage;

/// <summary>The conformance suite for <see cref="LocalFileSystem"/> on a new temporary directory.</summary>
public sealed class LocalFileSystemConformanceTests : FileSystemConformanceTests<LocalFileSystemConformanceTests.Fixture>
{
    public sealed class Fixture : IFileSystemFixture
    {
        private readonly string _tempDirectory = Path.Combine(Path.GetTempPath(), "freesftpsharp-tests", Guid.NewGuid().ToString("N"));

        public Fixture()
        {
            var root = Path.Combine(_tempDirectory, "root");
            Directory.CreateDirectory(root);
            FileSystem = new LocalFileSystem(root);
        }

        public IFileSystem FileSystem { get; }

        public StorageCapabilities ExpectedCapabilities => StorageCapabilities.RandomAccessWrite | StorageCapabilities.Append
            | StorageCapabilities.Rename | StorageCapabilities.SetTimes | StorageCapabilities.SetPermissions;

        public void Dispose()
        {
            try { Directory.Delete(_tempDirectory, recursive: true); } catch { }
        }
    }
}
