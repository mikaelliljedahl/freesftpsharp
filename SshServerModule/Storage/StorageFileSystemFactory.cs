#nullable enable
using System;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Storage;
using SshServerModule.Connections;
using SshServerModule.Events;

namespace SshServerModule.Storage
{
    /// <summary>
    /// The file system of a user: the storage of the user (<see cref="IUserStorageResolver"/>), created by the provider
    /// with that name (<see cref="IStorageProviderRegistry"/>), wrapped in the storage decorators. The decorator chain
    /// is built here, in one place, from the storage outwards:
    /// <list type="number">
    /// <item><see cref="EventingFileSystem"/>: the events of every operation that reaches it (#65); a hook can refuse
    /// an upload, download or delete here.</item>
    /// <item><see cref="ConnectionTrackingFileSystem"/>: the activity and open files of the connection in the registry
    /// (#57), for a client with a <see cref="ClientContext.ConnectionId"/>. Outermost, so a refused operation is
    /// activity too.</item>
    /// </list>
    /// </summary>
    public sealed class StorageFileSystemFactory : IFileSystemFactory
    {
        private readonly IStorageProviderRegistry _registry;
        private readonly IUserStorageResolver _resolver;
        private readonly IConnectionRegistry? _connections;
        private readonly IEventBus? _events;
        private readonly TimeProvider _time;

        /// <param name="connections">The open connections (AddSshServerConnections). Null: no connection tracking.</param>
        /// <param name="events">The event bus (AddSshServerEvents). Null: no events.</param>
        /// <param name="time">The clock of the events. Null: the system clock.</param>
        public StorageFileSystemFactory(IStorageProviderRegistry registry, IUserStorageResolver resolver, IConnectionRegistry? connections = null,
            IEventBus? events = null, TimeProvider? time = null)
        {
            _registry = registry;
            _resolver = resolver;
            _connections = connections;
            _events = events;
            _time = time ?? TimeProvider.System;
        }

        public async ValueTask<IFileSystem> CreateAsync(User user, ClientContext client, CancellationToken ct)
        {
            var storage = _resolver.Resolve(user);
            var fileSystem = await _registry.Get(storage.Provider).CreateAsync(storage.Options, ct);

            if (_events != null)
                fileSystem = new EventingFileSystem(fileSystem, _events, user, client, storage.Provider, _time);
            if (_connections != null && client.ConnectionId is { } connectionId)
                fileSystem = new ConnectionTrackingFileSystem(fileSystem, _connections, connectionId);
            return fileSystem;
        }
    }
}
