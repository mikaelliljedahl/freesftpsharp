using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.Encrypted;

/// <summary>
/// The encrypted local disk storage ("local-encrypted"): a <see cref="LocalFileSystem"/> on one directory, with the file
/// contents encrypted by <see cref="EncryptedFileSystem"/> and the keys of <see cref="IMasterKeyProvider"/>.
/// </summary>
public sealed class EncryptedLocalStorageProvider : StorageProvider<EncryptedLocalStorageOptions>
{
    public const string ProviderName = "local-encrypted";

    private readonly IMasterKeyProvider _keys;

    public EncryptedLocalStorageProvider(IMasterKeyProvider keys)
    {
        _keys = keys;
    }

    public override string Name => ProviderName;

    protected override IReadOnlyList<string> ValidateOptions(EncryptedLocalStorageOptions options)
        => string.IsNullOrWhiteSpace(options.RootDirectory) ? ["The root directory is not set."] : [];

    protected override async ValueTask<IFileSystem> CreateFileSystemAsync(EncryptedLocalStorageOptions options, CancellationToken ct)
    {
        // Fails here, before a session uses the storage, when the active key is missing or wrong.
        await _keys.GetActiveKeyAsync(ct);
        return new EncryptedFileSystem(new LocalFileSystem(options.RootDirectory), _keys);
    }
}
