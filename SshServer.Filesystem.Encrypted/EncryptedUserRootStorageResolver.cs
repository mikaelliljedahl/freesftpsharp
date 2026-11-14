using Microsoft.Extensions.Options;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.Encrypted;

/// <summary>
/// The storage of every user until the per-user storage configuration (#56): the local disk at
/// <see cref="User.UserRootDirectory"/>, encrypted ("local-encrypted") when <c>Storage:Encryption:Enabled</c> is true
/// and plain ("local") otherwise.
/// </summary>
public sealed class EncryptedUserRootStorageResolver : IUserStorageResolver
{
    private readonly bool _enabled;

    public EncryptedUserRootStorageResolver(IOptions<EncryptedStorageOptions> options)
    {
        _enabled = options.Value.Enabled;
    }

    public StorageSelection Resolve(User user) => _enabled
        ? new(EncryptedLocalStorageProvider.ProviderName, new EncryptedLocalStorageOptions(user.UserRootDirectory))
        : new(LocalDiskStorageProvider.ProviderName, new LocalDiskStorageOptions(user.UserRootDirectory));
}
