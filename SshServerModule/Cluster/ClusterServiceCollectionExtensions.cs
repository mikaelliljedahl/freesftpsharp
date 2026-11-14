#nullable enable
using System;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Cluster;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;

namespace SshServerModule.Cluster
{
    public static class ClusterServiceCollectionExtensions
    {
        /// <summary>
        /// Several nodes on one settings database (issue #75, <see cref="ClusterOptions"/>). Off by default: then it only
        /// registers the single-node services (<see cref="NoSettingsChanges"/>) and everything stays as on one node. With
        /// <c>Cluster:Enabled</c> it registers the <see cref="ClusterNodeService"/>, the <see cref="ClusterConnections"/> of
        /// all nodes, the shared bans and the settings version; the settings provider must be a SQL provider (the stores
        /// <see cref="IClusterStore"/>, <see cref="ISettingsVersionStore"/>, <see cref="IIpBanStore"/>).
        /// </summary>
        public static IServiceCollection AddSshServerCluster(this IServiceCollection services, IConfiguration configuration)
        {
            var options = FromConfiguration(configuration);
            services.AddSingleton(options);
            services.TryAddSingleton(TimeProvider.System);
            if (!options.Enabled)
            {
                services.TryAddSingleton<ISettingsChangeNotifier, NoSettingsChanges>();
                return services;
            }

            services.TryAddSingleton<ClusterSettingsChangeNotifier>();
            services.Replace(ServiceDescriptor.Singleton<ISettingsChangeNotifier>(sp => sp.GetRequiredService<ClusterSettingsChangeNotifier>()));
            // The connections of the other nodes; the registry counts their sessions for the session limit of a user (#149).
            services.TryAddSingleton(new RemoteConnections(options));
            services.Replace(ServiceDescriptor.Singleton<IRemoteSessionCounter>(sp => sp.GetRequiredService<RemoteConnections>()));
            services.TryAddSingleton(sp => new ClusterConnections(sp.GetRequiredService<IConnectionRegistry>(), sp.GetRequiredService<RemoteConnections>(),
                RequiredStore<IClusterStore>(sp), options, sp.GetRequiredService<TimeProvider>()));
            services.Replace(ServiceDescriptor.Singleton<IClusterConnections>(sp => sp.GetRequiredService<ClusterConnections>()));
            // Replaces the tracker of AddSshServerSecurity (TryAdd) in either order: the same tracker with the shared store.
            services.Replace(ServiceDescriptor.Singleton(sp => new LoginBanTracker(sp.GetRequiredService<TimeProvider>(),
                RequiredStore<IIpBanStore>(sp), sp.GetService<ILogger<LoginBanTracker>>())));
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventSink, SettingsVersionSink>());
            services.AddHostedService<ClusterNodeService>();
            return services;
        }

        /// <summary>Reads the <c>Cluster</c> section; an invalid value is an error at the start.</summary>
        public static ClusterOptions FromConfiguration(IConfiguration configuration)
        {
            var section = configuration.GetSection(ClusterOptions.SectionName);
            var enabledText = section["Enabled"];
            var enabled = false;
            if (!string.IsNullOrWhiteSpace(enabledText) && !bool.TryParse(enabledText.Trim(), out enabled))
                throw new InvalidOperationException("Cluster:Enabled must be true or false.");
            var secondsText = section["PollIntervalSeconds"];
            var seconds = 5;
            if (!string.IsNullOrWhiteSpace(secondsText)
                && !int.TryParse(secondsText.Trim(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out seconds))
                seconds = 0;
            if (seconds is < 1 or > 60)
                throw new InvalidOperationException("Cluster:PollIntervalSeconds must be between 1 and 60.");
            var nodeId = section["NodeId"]?.Trim();
            if (nodeId is { Length: > 128 })
                throw new InvalidOperationException("Cluster:NodeId must have at most 128 characters.");
            return new ClusterOptions
            {
                Enabled = enabled,
                NodeId = string.IsNullOrEmpty(nodeId) ? ClusterOptions.DefaultNodeId() : nodeId,
                PollInterval = TimeSpan.FromSeconds(seconds),
            };
        }

        private static T RequiredStore<T>(IServiceProvider services) where T : class
            => services.GetService<T>() ?? throw new InvalidOperationException(
                "Cluster:Enabled needs a SQL settings provider (Settings:Provider PostgreSQL, SqlServer or Sqlite), not LiteDb.");
    }
}
