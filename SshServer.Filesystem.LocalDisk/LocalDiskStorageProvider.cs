using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.LocalDisk;

/// <summary>The local disk storage ("local"): a <see cref="LocalFileSystem"/> on one directory.</summary>
public sealed class LocalDiskStorageProvider : StorageProvider<LocalDiskStorageOptions>
{
    public const string ProviderName = "local";

    public override string Name => ProviderName;

    protected override IReadOnlyList<string> ValidateOptions(LocalDiskStorageOptions options)
        => string.IsNullOrWhiteSpace(options.RootDirectory) ? ["The root directory is not set."] : [];

    protected override ValueTask<IFileSystem> CreateFileSystemAsync(LocalDiskStorageOptions options, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return ValueTask.FromResult<IFileSystem>(new LocalFileSystem(options.RootDirectory));
    }
}
