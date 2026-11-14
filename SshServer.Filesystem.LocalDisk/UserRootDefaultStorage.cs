using System.Text.Json;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.LocalDisk;

/// <summary>The storage of a user without a storage configuration: the local disk ("local") at <see cref="User.UserRootDirectory"/>.</summary>
public sealed class UserRootDefaultStorage : IDefaultUserStorage
{
    public StorageConfig For(User user) => new()
    {
        Provider = LocalDiskStorageProvider.ProviderName,
        Options = JsonSerializer.Serialize(new LocalDiskStorageOptions(user.UserRootDirectory)),
    };
}
