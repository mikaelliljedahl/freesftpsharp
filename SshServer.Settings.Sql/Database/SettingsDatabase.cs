using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SshServer.Settings.Sql.Database;

/// <summary>
/// The settings database of this process: the provider selected by <c>Settings:Provider</c> and the EF Core options for
/// it. The one place that picks a provider; every store gets its <see cref="Options"/>.
/// </summary>
public sealed class SettingsDatabase
{
    public SettingsDatabase(string providerName, DbContextOptions<SettingsDbContext> options)
    {
        ProviderName = providerName;
        Options = options;
    }

    /// <summary>The <see cref="ISettingsDatabaseProvider.Name"/> of the provider.</summary>
    public string ProviderName { get; }

    public DbContextOptions<SettingsDbContext> Options { get; }

    /// <summary>Finds the configured provider among the registered ones and builds its options.</summary>
    public static SettingsDatabase Create(SettingsStorageOptions options, IEnumerable<ISettingsDatabaseProvider> providers,
        string? baseDirectory = null)
    {
        var all = providers.ToList();
        var provider = all.FirstOrDefault(p => string.Equals(p.Name, options.Provider, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException(
                $"Unknown {SettingsStorageOptions.ProviderKey} '{options.Provider}'. Supported values: " +
                $"{string.Join(", ", all.Select(p => p.Name).Append(SettingsStorageOptions.LiteDbProviderName))}. " +
                "PostgreSQL and SqlServer need their package (AddPostgreSqlSettings, AddSqlServerSettings) in the host.");

        var builder = new DbContextOptionsBuilder<SettingsDbContext>();
        provider.Configure(builder, provider.ResolveConnectionString(options.ConfiguredConnectionString, baseDirectory ?? AppContext.BaseDirectory));
        return new SettingsDatabase(provider.Name, builder.Options);
    }
}

public static class SettingsDatabaseProviderServiceCollectionExtensions
{
    /// <summary>Makes a settings database provider available to <c>Settings:Provider</c>.</summary>
    public static IServiceCollection AddSettingsDatabaseProvider<TProvider>(this IServiceCollection services)
        where TProvider : class, ISettingsDatabaseProvider
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ISettingsDatabaseProvider, TProvider>());
        return services;
    }
}
