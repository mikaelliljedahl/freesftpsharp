using SshServer.Interfaces;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.LocalDisk;

/// <summary>
/// The storage of every user until the per-user storage configuration (#56): the local disk at
/// <see cref="User.UserRootDirectory"/>.
/// </summary>
public sealed class UserRootStorageResolver : IUserStorageResolver
{
    public StorageSelection Resolve(User user)
        => new(LocalDiskStorageProvider.ProviderName, new LocalDiskStorageOptions(user.UserRootDirectory));
}
