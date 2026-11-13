using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage;

/// <summary>The conformance suite for <see cref="InMemoryFileSystem"/> with every capability.</summary>
public sealed class InMemoryFileSystemConformanceTests : FileSystemConformanceTests<InMemoryFileSystemConformanceTests.Fixture>
{
    public sealed class Fixture : IFileSystemFixture
    {
        public IFileSystem FileSystem { get; } = new InMemoryFileSystem();
        public StorageCapabilities ExpectedCapabilities => InMemoryFileSystem.AllCapabilities;
        public void Dispose() { }
    }
}

/// <summary>
/// The conformance suite for an <see cref="InMemoryFileSystem"/> without capabilities, which behaves like an object
/// store (sequential writes only, no rename, no times, no permissions): the suite checks that every operation that needs
/// a missing capability throws <see cref="FileSystemError.OpNotSupported"/>.
/// </summary>
public sealed class InMemoryObjectStoreConformanceTests : FileSystemConformanceTests<InMemoryObjectStoreConformanceTests.Fixture>
{
    public sealed class Fixture : IFileSystemFixture
    {
        public IFileSystem FileSystem { get; } = new InMemoryFileSystem(StorageCapabilities.None);
        public StorageCapabilities ExpectedCapabilities => StorageCapabilities.None;
        public void Dispose() { }
    }
}
