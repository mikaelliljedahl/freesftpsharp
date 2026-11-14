using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Quotas;
using SshServerModule.Quotas;
using SshServer.Interfaces.Users;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Storage;

namespace SshServerModule.Storage
{
    public static class StorageServiceCollectionExtensions
    {
        /// <summary>
        /// The storage core: <see cref="IStorageProviderRegistry"/> over every registered <see cref="IStorageProvider"/>,
        /// the <see cref="IFileSystemFactory"/> of the sessions, the <see cref="IUserStorageResolver"/> (per-user storage and
        /// virtual folders), the <see cref="StorageOptionsCodec"/>, the <see cref="IEffectiveUserSettingsService"/> (the
        /// settings of a user with its groups, for the permission decorator, the storage and the login), and the application services of the admin UI (<see cref="StorageConfigService"/>,
        /// <see cref="VirtualFolderService"/>). Register at least one backend too, for example
        /// <c>services.AddLocalDiskStorage()</c>. Without a registered <see cref="ISecretProtector"/> (AddSshServerSettings
        /// registers one) a storage configuration cannot have secrets.
        /// <para>
        /// The quotas and bandwidth limits (#62): <see cref="IEffectiveQuotaService"/>, the counters (<see cref="QuotaUsageTracker"/>
        /// over an <see cref="IQuotaUsageStore"/>: in memory unless AddSshServerSettings registers the database store), the
        /// decorators of the factory, the scan (<see cref="QuotaScanService"/>, section <c>Quota</c>) and the flush of the
        /// counters as hosted services, the sink that follows the user changes, and the event rule actions "QuotaScan" and
        /// "QuotaResetTransfer". A user without a quota costs nothing.
        /// </para>
        /// </summary>
        public static IServiceCollection AddSshServerStorage(this IServiceCollection services)
        {
            services.TryAddSingleton<IStorageProviderRegistry, StorageProviderRegistry>();
            services.TryAddSingleton<IEffectiveUserSettingsService>(sp => new EffectiveUserSettingsService(sp.GetService<SshServer.Interfaces.ISettingsRepository>()));
            services.TryAddSingleton<IFileSystemFactory, StorageFileSystemFactory>();
            services.TryAddSingleton<IUserStorageResolver, UserStorageResolver>();
            services.TryAddSingleton<ISecretProtector, UnavailableSecretProtector>();
            services.TryAddSingleton<StorageOptionsCodec>();
            services.TryAddSingleton<StorageConfigService>();
            services.TryAddSingleton<VirtualFolderService>();

            services.TryAddSingleton(TimeProvider.System);
            services.TryAddSingleton<IEffectiveQuotaService, EffectiveQuotaService>();
            services.TryAddSingleton<IQuotaUsageStore, InMemoryQuotaUsageStore>();
            services.TryAddSingleton<QuotaUsageTracker>();
            services.TryAddSingleton<QuotaScanQueue>();
            services.TryAddSingleton<QuotaDecorators>();
            services.TryAddSingleton<QuotaScanService>();
            services.AddHostedService(sp => sp.GetRequiredService<QuotaScanService>());
            services.AddHostedService<QuotaUsageFlushService>();
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventSink, QuotaProviderEventSink>());
            // The event rule actions "Rescan quota" and "Reset transfer quota" (#68): used only with AddEventRules.
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventRuleAction, QuotaScanRuleAction>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventRuleAction, QuotaResetTransferRuleAction>());
            services.AddOptions<QuotaOptions>()
                .Configure<IServiceProvider>((options, sp) =>
                {
                    if (sp.GetService<IConfiguration>() is { } configuration)
                        QuotaOptions.Bind(options, configuration);
                })
                .ValidateOnStart();
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<QuotaOptions>, QuotaOptionsValidator>());
            return services;
        }
    }
}
