using System.Text.Json;
using Microsoft.Extensions.Options;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.Encrypted;

/// <summary>
/// The storage of a user without a storage configuration: the local disk at <see cref="User.UserRootDirectory"/>,
/// encrypted ("local-encrypted") when <c>Storage:Encryption:Enabled</c> is true and plain ("local") otherwise. A user
/// with a storage configuration (issue #56) gets the provider of that configuration instead.
/// </summary>
public sealed class EncryptedUserRootDefaultStorage : IDefaultUserStorage
{
    private readonly bool _enabled;
    private readonly UserRootDefaultStorage _plain = new();

    public EncryptedUserRootDefaultStorage(IOptions<EncryptedStorageOptions> options)
    {
        _enabled = options.Value.Enabled;
    }

    public StorageConfig For(User user) => _enabled
        ? new StorageConfig
        {
            Provider = EncryptedLocalStorageProvider.ProviderName,
            Options = JsonSerializer.Serialize(new EncryptedLocalStorageOptions(user.UserRootDirectory)),
        }
        : _plain.For(user);
}
