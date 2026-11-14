using Microsoft.EntityFrameworkCore;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.Database;

namespace SshServer.Settings.SqlServer;

/// <summary>
/// SQL Server (or Azure SQL) for the settings (<c>Settings:Provider</c> = <c>SqlServer</c>, issue #75), for several nodes
/// on one database. <c>ConnectionStrings:Settings</c> is a SqlClient connection string. The migrations are in this
/// assembly. The names compare without case through the default collation of the database (keep a <c>_CI_</c> collation).
/// </summary>
public sealed class SqlServerSettingsDatabaseProvider : ISettingsDatabaseProvider
{
    public const string ProviderName = "SqlServer";

    public string Name => ProviderName;

    public string ResolveConnectionString(string? configured, string baseDirectory)
    {
        if (string.IsNullOrWhiteSpace(configured))
            throw new InvalidOperationException(
                $"{SettingsStorageOptions.ProviderKey} is {ProviderName}, but ConnectionStrings:{SettingsStorageOptions.ConnectionStringName} is not set.");
        return configured;
    }

    public void Configure(DbContextOptionsBuilder<SettingsDbContext> builder, string connectionString)
        => builder.UseSqlServer(connectionString, o => o.MigrationsAssembly(typeof(SqlServerSettingsDatabaseProvider).Assembly.GetName().Name));
}
