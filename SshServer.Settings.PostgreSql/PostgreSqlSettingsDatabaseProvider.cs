using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.Database;

namespace SshServer.Settings.PostgreSql;

/// <summary>
/// PostgreSQL for the settings (<c>Settings:Provider</c> = <c>PostgreSQL</c>, issue #75), for several nodes on one
/// database. <c>ConnectionStrings:Settings</c> is an Npgsql connection string
/// (<c>Host=db;Database=freesftpsharp;Username=...;Password=...</c>). The migrations are in this assembly; the database
/// needs the citext extension (the first migration creates it; the user needs the CREATE privilege on the database).
/// </summary>
public sealed class PostgreSqlSettingsDatabaseProvider : ISettingsDatabaseProvider
{
    public const string ProviderName = "PostgreSQL";

    public string Name => ProviderName;

    public string ResolveConnectionString(string? configured, string baseDirectory)
    {
        if (string.IsNullOrWhiteSpace(configured))
            throw new InvalidOperationException(
                $"{SettingsStorageOptions.ProviderKey} is {ProviderName}, but ConnectionStrings:{SettingsStorageOptions.ConnectionStringName} is not set.");
        return configured;
    }

    public void Configure(DbContextOptionsBuilder<SettingsDbContext> builder, string connectionString)
    {
        builder.UseNpgsql(connectionString, o => o.MigrationsAssembly(typeof(PostgreSqlSettingsDatabaseProvider).Assembly.GetName().Name));
        builder.ReplaceService<IModelCustomizer, PostgreSqlModelCustomizer>();
    }
}
