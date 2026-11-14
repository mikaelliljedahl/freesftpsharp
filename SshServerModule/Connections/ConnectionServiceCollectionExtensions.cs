using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces.Connections;

namespace SshServerModule.Connections
{
    public static class ConnectionServiceCollectionExtensions
    {
        /// <summary>
        /// Registers the <see cref="IConnectionRegistry"/> of the open connections as a singleton, shared by the protocols
        /// and the admin UI. Call it together with AddHostedService&lt;HostedServer&gt;.
        /// </summary>
        public static IServiceCollection AddSshServerConnections(this IServiceCollection services)
        {
            services.TryAddSingleton(TimeProvider.System);
            services.TryAddSingleton<IConnectionRegistry, ConnectionRegistry>();
            return services;
        }
    }
}
