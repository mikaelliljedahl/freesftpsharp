using FxSsh.SshServerModule;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces;

namespace SshServer.Settings.Sql
{
    public static class Startup
    {
        /// <summary>
        /// Registers the <see cref="ISettingsRepository"/> selected by the configuration
        /// (see <see cref="SettingsStorageOptions"/>): SQLite by default, LiteDB when <c>Settings:Provider</c> is <c>LiteDb</c>.
        /// </summary>
        public static IServiceCollection AddSshServerSettings(this IServiceCollection services, IConfiguration configuration)
        {
            var options = SettingsStorageOptions.FromConfiguration(configuration);
            services.AddSingleton(options);

            switch (options.Provider)
            {
                case SettingsProvider.Sqlite:
                    services.AddSingleton<ISettingsRepository>(sp => new SqlSettingsRepository(
                        CreateDbContextOptions(options),
                        sp.GetService<ILogger<SqlSettingsRepository>>(),
                        options.LiteDbPath));
                    break;

                case SettingsProvider.LiteDb:
                    services.AddSingleton<ISettingsRepository>(_ => new SettingsRepository(options.LiteDbPath));
                    break;

                default:
                    throw new InvalidOperationException($"Unsupported settings provider {options.Provider}.");
            }

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
