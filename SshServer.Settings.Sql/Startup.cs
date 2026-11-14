using FxSsh.SshServerModule;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Audit;
using SshServer.Interfaces.Events;
using SshServer.Settings.Sql.Admins;
using SshServer.Settings.Sql.Api;
using SshServer.Interfaces.Api;
using SshServer.Settings.Sql.Audit;
using SshServer.Settings.Sql.Webhooks;
using SshServer.Settings.Sql.Quotas;
using SshServer.Interfaces.Quotas;
using SshServer.Settings.Sql.EventRules;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Webhooks;
using SshServer.Interfaces.TwoFactor;
using SshServer.Settings.Sql.TwoFactor;
using Microsoft.Extensions.Options;
using SshServer.Settings.Sql.Database;
using SshServer.Settings.Sql.Cluster;
using SshServer.Interfaces.Cluster;

namespace SshServer.Settings.Sql
{
    public static class Startup
    {
        /// <summary>
        /// Registers the <see cref="ISettingsRepository"/> selected by the configuration
        /// (see <see cref="SettingsStorageOptions"/>): SQLite by default, PostgreSQL or SQL Server (#75) when their provider
        /// is registered and selected, LiteDB when <c>Settings:Provider</c> is <c>LiteDb</c>.
        /// With a SQL provider it registers the audit log too: <see cref="IAuditLog"/> in the same database, the
        /// <see cref="AuditSink"/> on the event bus and the nightly <see cref="AuditRetentionService"/> (<c>Audit:RetentionDays</c>),
        /// the store of the webhooks (<see cref="IWebhookStore"/>; the webhooks plug-in, AddWebhooks, uses it), the store
        /// of the event rules (<see cref="IEventRuleStore"/>; the event rules plug-in, AddEventRules, uses it) and the store
        /// of the quota counters (<see cref="IQuotaUsageStore"/>, #62).
        /// Registers the encryption of the stored storage secrets too (<see cref="SecretProtection"/>).
        /// The administrators and scope roles (<see cref="IAdminStore"/>, #60) are in the same database; the LiteDB
        /// provider keeps them in memory only. The TOTP enrolments (<see cref="ITwoFactorStore"/>, #63) are in the same
        /// database; the LiteDB provider has none. The REST API keys and the token signing key (<see cref="IApiKeyStore"/>,
        /// <see cref="IApiSigningKeyStore"/>, #67) are in the same database; the LiteDB provider keeps them in memory only.
        /// </summary>
        public static IServiceCollection AddSshServerSettings(this IServiceCollection services, IConfiguration configuration)
        {
            var options = SettingsStorageOptions.FromConfiguration(configuration);
            services.AddSingleton(options);
            services.AddSshServerSecretProtection();

            if (options.IsLiteDb)
            {
                services.AddSingleton<ISettingsRepository>(_ => new SettingsRepository(options.LiteDbPath));
                services.TryAddSingleton<IAuditLog, DisabledAuditLog>();
                services.TryAddSingleton<IWebhookStore, DisabledWebhookStore>();
                services.TryAddSingleton<IEventRuleStore, DisabledEventRuleStore>();
                services.TryAddSingleton<IAdminStore, InMemoryAdminStore>();
                services.TryAddSingleton<InMemoryApiKeyStore>();
                services.TryAddSingleton<IApiKeyStore>(sp => sp.GetRequiredService<InMemoryApiKeyStore>());
                services.TryAddSingleton<IApiSigningKeyStore>(sp => sp.GetRequiredService<InMemoryApiKeyStore>());
                services.TryAddSingleton<ITwoFactorStore, DisabledTwoFactorStore>();
            }
            else
            {
                AddSqlStores(services, configuration, options);
            }

            services.TryAddSingleton<UserAdministrationService>();
            services.TryAddSingleton(sp => new AdminAdministrationService(
                sp.GetRequiredService<IAdminStore>(),
                sp.GetRequiredService<ISettingsRepository>(),
                sp.GetService<IEventBus>(),
                sp.GetService<TimeProvider>()));
            return services;
        }

        /// <summary>
        /// The stores of an EF Core provider (<see cref="SettingsDatabase"/>, selected by <c>Settings:Provider</c> from the
        /// registered <see cref="ISettingsDatabaseProvider"/>s: SQLite is built in).
        /// </summary>
        private static void AddSqlStores(IServiceCollection services, IConfiguration configuration, SettingsStorageOptions options)
        {
            services.AddSettingsDatabaseProvider<SqliteSettingsDatabaseProvider>();
            services.TryAddSingleton(sp => SettingsDatabase.Create(options, sp.GetServices<ISettingsDatabaseProvider>()));
            static DbContextOptions<SettingsDbContext> Db(IServiceProvider sp) => sp.GetRequiredService<SettingsDatabase>().Options;

            services.AddSingleton<ISettingsRepository>(sp => new SqlSettingsRepository(
                Db(sp),
                sp.GetService<ILogger<SqlSettingsRepository>>(),
                options.LiteDbPath,
                events: sp.GetService<IEventBus>(),
                time: sp.GetService<TimeProvider>()));
            services.TryAddSingleton<IAuditLog>(sp => new SqlAuditLog(Db(sp)));
            // Like the audit log: the repository creates and migrates the database when the host starts. The store
            // does not resolve the repository (that would be a cycle: repository, event bus, webhook sink, store).
            services.TryAddSingleton<IWebhookStore>(sp => new SqlWebhookStore(Db(sp)));
            services.TryAddSingleton<IEventRuleStore>(sp => new SqlEventRuleStore(Db(sp)));
            // The quota counters (#62) are shared by the nodes. AddSingleton, not TryAdd: it replaces the in-memory
            // store of AddSshServerStorage in either order. Like the webhook store, it does not resolve the repository.
            services.AddSingleton<IQuotaUsageStore>(sp => new SqlQuotaUsageStore(Db(sp)));
            services.TryAddSingleton<IAdminStore>(sp =>
            {
                // The repository creates and migrates the database; the store only uses the tables.
                sp.GetRequiredService<ISettingsRepository>();
                return new SqlAdminStore(Db(sp));
            });
            services.TryAddSingleton(sp =>
            {
                sp.GetRequiredService<ISettingsRepository>();
                return new SqlApiKeyStore(Db(sp));
            });
            services.TryAddSingleton<IApiKeyStore>(sp => sp.GetRequiredService<SqlApiKeyStore>());
            services.TryAddSingleton<IApiSigningKeyStore>(sp => sp.GetRequiredService<SqlApiKeyStore>());
            services.TryAddSingleton<ITwoFactorStore>(sp =>
            {
                sp.GetRequiredService<ISettingsRepository>(); // creates and migrates the database
                return new SqlTwoFactorStore(Db(sp));
            });
            // The shared state of several nodes (#75); used only with Cluster:Enabled (AddSshServerCluster).
            services.TryAddSingleton(sp => new SqlClusterStore(Db(sp)));
            services.TryAddSingleton<IClusterStore>(sp => sp.GetRequiredService<SqlClusterStore>());
            services.TryAddSingleton<ISettingsVersionStore>(sp => sp.GetRequiredService<SqlClusterStore>());
            services.TryAddSingleton<IIpBanStore>(sp => new SqlIpBanStore(Db(sp)));
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventSink, AuditSink>());
            services.TryAddSingleton(TimeProvider.System);
            services.AddOptions<AuditOptions>().Configure(o => AuditOptions.Bind(o, configuration)).ValidateOnStart();
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<AuditOptions>, AuditOptionsValidator>());
            services.AddHostedService<AuditRetentionService>();
        }
    }
}
