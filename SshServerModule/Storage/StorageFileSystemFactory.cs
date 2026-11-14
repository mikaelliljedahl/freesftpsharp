#nullable enable
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;
using SshServerModule.Connections;
using SshServerModule.Events;
using SshServerModule.Quotas;

namespace SshServerModule.Storage
{
    /// <summary>
    /// The file system of a user: the storage of the user (<see cref="IUserStorageResolver"/>: <see cref="User.Storage"/> or
    /// the default local disk, and the mounted virtual folders), each created by the provider with its name
    /// (<see cref="IStorageProviderRegistry"/>) from its decoded options (<see cref="StorageOptionsCodec"/>), wrapped in the
    /// storage decorators. The decorator chain is built here and only here, innermost first:
    /// <list type="number">
    /// <item><see cref="DiskQuotaFileSystem"/> around each storage with a disk quota (#62): the own storage of the user
    /// and each virtual folder is one quota scope. Left out for a storage without a quota.</item>
    /// <item><see cref="MountedFileSystem"/>: routes the paths of the virtual folders to their storage (#56); left out
    /// for a user without virtual folders. Every rule below sees the virtual paths of the user.</item>
    /// <item><see cref="TransferQuotaFileSystem"/> and <see cref="BandwidthFileSystem"/>: the transfer quota and the
    /// bandwidth of the session (#62), over every storage of the user; each left out without its limit, and both for an
    /// operation of the server itself (<see cref="ClientContext.SkipPermissions"/>). Inside the
    /// permissions, so a refused operation is not counted.</item>
    /// <item><see cref="PermissionFileSystem"/>: per-path permissions and path filters (#59); left out for a user who
    /// may do everything, and for an operation of the server itself (<see cref="ClientContext.SkipPermissions"/>, the
    /// actions of the event rules).</item>
    /// <item><see cref="EventingFileSystem"/>: the events of every operation of the client (#65). Outside the
    /// permissions, so an operation that the permissions refuse still gives an event (status Error) in the audit log;
    /// a hook can refuse an upload, download or delete before the permissions are checked.</item>
    /// <item><see cref="ConnectionTrackingFileSystem"/>: the activity and open files of the connection in the registry
    /// (#57), for a client with a <see cref="ClientContext.ConnectionId"/>. Outermost, so every request is activity.</item>
    /// </list>
    /// </summary>
    public sealed class StorageFileSystemFactory : IFileSystemFactory
    {
        private readonly IStorageProviderRegistry _registry;
        private readonly IUserStorageResolver _resolver;
        private readonly StorageOptionsCodec _codec;
        private readonly IEffectivePermissionsService _permissions;
        private readonly IConnectionRegistry? _connections;
        private readonly IEventBus? _events;
        private readonly TimeProvider _time;
        private readonly QuotaDecorators? _quotas;

        /// <param name="connections">The open connections (AddSshServerConnections). Null: no connection tracking.</param>
        /// <param name="events">The event bus (AddSshServerEvents). Null: no events.</param>
        /// <param name="time">The clock of the events. Null: the system clock.</param>
        /// <param name="quotas">The quota decorators (AddSshServerStorage). Null: no quotas and no bandwidth limits.</param>
        public StorageFileSystemFactory(IStorageProviderRegistry registry, IUserStorageResolver resolver, StorageOptionsCodec codec,
            IEffectivePermissionsService permissions, IConnectionRegistry? connections = null, IEventBus? events = null, TimeProvider? time = null,
            QuotaDecorators? quotas = null)
        {
            _quotas = quotas;
            _registry = registry;
            _resolver = resolver;
            _codec = codec;
            _permissions = permissions;
            _connections = connections;
            _events = events;
            _time = time ?? TimeProvider.System;
        }

        public async ValueTask<IFileSystem> CreateAsync(User user, ClientContext client, CancellationToken ct)
        {
            var storage = _resolver.Resolve(user);
            var quotas = _quotas?.Resolve(user) ?? EffectiveQuotas.Unlimited;
            var fileSystem = await CreateStorageAsync(storage.Root, ct);
            if (_quotas != null)
                fileSystem = await _quotas.WrapStorageAsync(fileSystem, QuotaScope.ForUser(user.Username), quotas.Disk, ct);
            if (storage.Mounts.Count > 0)
            {
                var mounts = new List<MountedFileSystem.Mount>();
                foreach (var mount in storage.Mounts)
                {
                    try
                    {
                        var mounted = await CreateStorageAsync(mount.Storage, ct);
                        if (_quotas != null)
                            mounted = await _quotas.WrapStorageAsync(mounted, QuotaScope.ForFolder(mount.FolderId), quotas.ForMount(mount.Path), ct);
                        mounts.Add(new MountedFileSystem.Mount(mount.Path, mounted));
                    }
                    catch (Exception ex) when (ex is ArgumentException or KeyNotFoundException or FileSystemException)
                    {
                        throw new ArgumentException($"The virtual folder '{mount.Name}' at {mount.Path}: {ex.Message}", ex);
                    }
                }
                fileSystem = new MountedFileSystem(fileSystem, mounts);
            }
            // An operation of the server itself (an event rule action) is not a transfer of the client: no transfer quota or bandwidth.
            if (_quotas != null && !client.SkipPermissions)
                fileSystem = await _quotas.WrapSessionAsync(fileSystem, user, quotas, client, ct);
            if (!client.SkipPermissions)
                fileSystem = PermissionFileSystem.Wrap(fileSystem, _permissions.Resolve(user));
            if (_events != null)
                fileSystem = new EventingFileSystem(fileSystem, _events, user, client, storage.Root.Provider, _time);
            if (_connections != null && client.ConnectionId is { } connectionId)
                fileSystem = new ConnectionTrackingFileSystem(fileSystem, _connections, connectionId);
            return fileSystem;
        }

        private async ValueTask<IFileSystem> CreateStorageAsync(StorageConfig config, CancellationToken ct)
        {
            var provider = _registry.Get(config.Provider);
            return await provider.CreateAsync(_codec.Decode(config), ct);
        }
    }
}
