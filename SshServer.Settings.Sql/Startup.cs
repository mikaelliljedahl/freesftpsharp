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
using SshServer.Settings.Sql.EventRules;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Webhooks;
using SshServer.Interfaces.TwoFactor;
using SshServer.Settings.Sql.TwoFactor;
using Microsoft.Extensions.Options;

namespace SshServer.Settings.Sql
{
    public static class Startup
    {
        /// <summary>
        /// Registers the <see cref="ISettingsRepository"/> selected by the configuration
        /// (see <see cref="SettingsStorageOptions"/>): SQLite by default, LiteDB when <c>Settings:Provider</c> is <c>LiteDb</c>.
        /// With SQLite it registers the audit log too: <see cref="IAuditLog"/> in the same database, the
        /// <see cref="AuditSink"/> on the event bus and the nightly <see cref="AuditRetentionService"/> (<c>Audit:RetentionDays</c>),
        /// the store of the webhooks (<see cref="IWebhookStore"/>; the webhooks plug-in, AddWebhooks, uses it) and the store
        /// of the event rules (<see cref="IEventRuleStore"/>; the event rules plug-in, AddEventRules, uses it).
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

            switch (options.Provider)
            {
                case SettingsProvider.Sqlite:
                    var dbOptions = CreateDbContextOptions(options);
                    services.AddSingleton<ISettingsRepository>(sp => new SqlSettingsRepository(
                        dbOptions,
                        sp.GetService<ILogger<SqlSettingsRepository>>(),
                        options.LiteDbPath,
                        events: sp.GetService<IEventBus>(),
                        time: sp.GetService<TimeProvider>()));
                    services.TryAddSingleton<IAuditLog>(_ => new SqlAuditLog(dbOptions));
                    // Like the audit log: the repository creates and migrates the database when the host starts. The store
                    // does not resolve the repository (that would be a cycle: repository, event bus, webhook sink, store).
                    services.TryAddSingleton<IWebhookStore>(_ => new SqlWebhookStore(dbOptions));
                    services.TryAddSingleton<IEventRuleStore>(_ => new SqlEventRuleStore(dbOptions));
                    services.TryAddSingleton<IAdminStore>(sp =>
                    {
                        // The repository creates and migrates the database; the store only uses the tables.
                        sp.GetRequiredService<ISettingsRepository>();
                        return new SqlAdminStore(dbOptions);
                    });
                    services.TryAddSingleton(sp =>
                    {
                        sp.GetRequiredService<ISettingsRepository>();
                        return new SqlApiKeyStore(dbOptions);
                    });
                    services.TryAddSingleton<IApiKeyStore>(sp => sp.GetRequiredService<SqlApiKeyStore>());
                    services.TryAddSingleton<IApiSigningKeyStore>(sp => sp.GetRequiredService<SqlApiKeyStore>());
                    services.TryAddSingleton<ITwoFactorStore>(sp =>
                    {
                        sp.GetRequiredService<ISettingsRepository>(); // creates and migrates the database
                        return new SqlTwoFactorStore(dbOptions);
                    });
                    services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventSink, AuditSink>());
                    services.TryAddSingleton(TimeProvider.System);
                    services.AddOptions<AuditOptions>().Configure(o => AuditOptions.Bind(o, configuration)).ValidateOnStart();
                    services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<AuditOptions>, AuditOptionsValidator>());
                    services.AddHostedService<AuditRetentionService>();
                    break;

                case SettingsProvider.LiteDb:
                    services.AddSingleton<ISettingsRepository>(_ => new SettingsRepository(options.LiteDbPath));
                    services.TryAddSingleton<IAuditLog, DisabledAuditLog>();
                    services.TryAddSingleton<IWebhookStore, DisabledWebhookStore>();
                    services.TryAddSingleton<IEventRuleStore, DisabledEventRuleStore>();
                    services.TryAddSingleton<IAdminStore, InMemoryAdminStore>();
                    services.TryAddSingleton<InMemoryApiKeyStore>();
                    services.TryAddSingleton<IApiKeyStore>(sp => sp.GetRequiredService<InMemoryApiKeyStore>());
                    services.TryAddSingleton<IApiSigningKeyStore>(sp => sp.GetRequiredService<InMemoryApiKeyStore>());
                    services.TryAddSingleton<ITwoFactorStore, DisabledTwoFactorStore>();
                    break;

                default:
                    throw new InvalidOperationException($"Unsupported settings provider {options.Provider}.");
            }

            services.TryAddSingleton<UserAdministrationService>();
            services.TryAddSingleton(sp => new AdminAdministrationService(
                sp.GetRequiredService<IAdminStore>(),
                sp.GetRequiredService<ISettingsRepository>(),
                sp.GetService<IEventBus>(),
                sp.GetService<TimeProvider>()));
            return services;
        }

        /// <summary>The EF Core options for a SQL provider. Add another EF Core provider (e.g. SQL Server) here.</summary>
        public static DbContextOptions<SettingsDbContext> CreateDbContextOptions(SettingsStorageOptions options)
        {
            var builder = new DbContextOptionsBuilder<SettingsDbContext>();
            switch (options.Provider)
            {
                case SettingsProvider.Sqlite:
                    builder.UseSqlite(options.ConnectionString);
                    break;
                default:
                    throw new InvalidOperationException($"{options.Provider} is not an EF Core settings provider.");
            }
            return builder.Options;
        }
    }
}
