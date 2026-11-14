using System;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;

namespace SshServerModule.Connections
{
    public static class ConnectionServiceCollectionExtensions
    {
        /// <summary>
        /// Registers the <see cref="IConnectionRegistry"/> of the open connections as a singleton, shared by the protocols
        /// and the admin UI. Call it together with AddHostedService&lt;HostedServer&gt;. With the event bus
        /// (AddSshServerEvents), <see cref="UserSessionCloser"/> closes the sessions of a disabled or removed user, and
        /// <see cref="UserLifecycleService"/> those of a user that expired (needs the settings repository).
        /// </summary>
        public static IServiceCollection AddSshServerConnections(this IServiceCollection services)
        {
            services.TryAddSingleton(TimeProvider.System);
            services.TryAddSingleton<IConnectionRegistry, ConnectionRegistry>();
            // The closer is a sink of the event bus and publishes to it, so it asks for the bus only when it needs it.
            if (!services.Any(d => d.ServiceType == typeof(UserSessionCloser)))
            {
                services.AddSingleton(sp => new UserSessionCloser(sp.GetRequiredService<IConnectionRegistry>(),
                    () => sp.GetService<IEventBus>(), sp.GetRequiredService<TimeProvider>(), sp.GetService<ILogger<UserSessionCloser>>()));
                services.AddSingleton<IEventSink>(sp => sp.GetRequiredService<UserSessionCloser>());
            }
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, UserLifecycleService>());
            return services;
        }
    }
}
