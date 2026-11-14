#nullable enable
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Storage
{
    /// <summary>
    /// The file system of a user: the storage of the user (<see cref="IUserStorageResolver"/>), created by the provider
    /// with that name (<see cref="IStorageProviderRegistry"/>), wrapped in the storage decorators. The decorator chain is
    /// built here and only here, innermost first:
    /// <list type="number">
    /// <item><see cref="PermissionFileSystem"/>: per-path permissions and path filters (#59); left out for a user who
    /// may do everything.</item>
    /// </list>
    /// </summary>
    public sealed class StorageFileSystemFactory : IFileSystemFactory
    {
        private readonly IStorageProviderRegistry _registry;
        private readonly IUserStorageResolver _resolver;
        private readonly IEffectivePermissionsService _permissions;

        public StorageFileSystemFactory(IStorageProviderRegistry registry, IUserStorageResolver resolver, IEffectivePermissionsService permissions)
        {
            _registry = registry;
            _resolver = resolver;
            _permissions = permissions;
        }

        public async ValueTask<IFileSystem> CreateAsync(User user, CancellationToken ct)
        {
            var storage = _resolver.Resolve(user);
            var fileSystem = await _registry.Get(storage.Provider).CreateAsync(storage.Options, ct);
            fileSystem = PermissionFileSystem.Wrap(fileSystem, _permissions.Resolve(user));
            return fileSystem;
        }
    }
}
