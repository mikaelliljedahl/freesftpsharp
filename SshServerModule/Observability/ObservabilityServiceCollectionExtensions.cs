#nullable enable
using Microsoft.Extensions.DependencyInjection;
using System.Linq;
using SshServer.Interfaces.Events;
using SshServerModule.Connections;
using SshServerModule.Events;

namespace SshServerModule.Observability
{
    public static class ObservabilityServiceCollectionExtensions
    {
        /// <summary>
        /// Produces the server metrics and trace activities (<see cref="FreeSftpSharpMetrics"/>) from the connection registry and
        /// the event bus. It opens no port and needs no exporter: nothing leaves the process until an exporter
        /// (SshServer.Observability) subscribes to <see cref="Telemetry.MeterName"/>.
        /// </summary>
        public static IServiceCollection AddSshServerMetrics(this IServiceCollection services)
        {
            services.AddSshServerConnections();
            services.AddSshServerEvents();
            if (services.All(d => d.ServiceType != typeof(FreeSftpSharpMetrics))) // once, also when called twice
            {
                services.AddSingleton<FreeSftpSharpMetrics>();
                services.AddSingleton<IEventSink>(sp => sp.GetRequiredService<FreeSftpSharpMetrics>());
            }
            return services;
        }
    }
}
