#nullable enable
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Storage
{
    /// <summary>
    /// The file system of a user: the storage of the user (<see cref="IUserStorageResolver"/>), created by the provider
    /// with that name (<see cref="IStorageProviderRegistry"/>). The storage decorators (permissions, quotas, events) are
    /// chained here, in one place, when they come.
    /// </summary>
    public sealed class StorageFileSystemFactory : IFileSystemFactory
    {
        private readonly IStorageProviderRegistry _registry;
        private readonly IUserStorageResolver _resolver;

        public StorageFileSystemFactory(IStorageProviderRegistry registry, IUserStorageResolver resolver)
        {
            _registry = registry;
            _resolver = resolver;
        }

        public ValueTask<IFileSystem> CreateAsync(User user, CancellationToken ct)
        {
            var storage = _resolver.Resolve(user);
            return _registry.Get(storage.Provider).CreateAsync(storage.Options, ct);
        }
    }
}
