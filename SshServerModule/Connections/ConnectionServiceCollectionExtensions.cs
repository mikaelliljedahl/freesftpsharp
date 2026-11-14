using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;

namespace SshServerModule.Connections
{
    public static class ConnectionServiceCollectionExtensions
    {
        /// <summary>
        /// Registers the <see cref="IConnectionRegistry"/> of the open connections as a singleton, shared by the protocols
        /// and the admin UI. Call it together with AddHostedService&lt;HostedServer&gt;. With the event bus
        /// (AddSshServerEvents), <see cref="DisabledUserDisconnector"/> closes the sessions of a disabled or removed user.
        /// </summary>
        public static IServiceCollection AddSshServerConnections(this IServiceCollection services)
        {
            services.TryAddSingleton(TimeProvider.System);
            services.TryAddSingleton<IConnectionRegistry, ConnectionRegistry>();
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventSink, DisabledUserDisconnector>());
            return services;
        }
    }
}
