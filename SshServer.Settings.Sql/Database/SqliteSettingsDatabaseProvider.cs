using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace SshServer.Settings.Sql.Database;

/// <summary>
/// SQLite, the default provider (zero configuration: <c>freesftpsharp.db</c> next to the app). Its migrations are in
/// this assembly (<c>Migrations/Sqlite</c>).
/// </summary>
public sealed class SqliteSettingsDatabaseProvider : ISettingsDatabaseProvider
{
    public const string ProviderName = "Sqlite";

    public string Name => ProviderName;

    public string ResolveConnectionString(string? configured, string baseDirectory) => ResolveSqliteConnectionString(configured, baseDirectory);

    public void Configure(DbContextOptionsBuilder<SettingsDbContext> builder, string connectionString) => builder.UseSqlite(connectionString);

    /// <summary>
    /// Uses the default file next to the app when nothing is configured, and makes a relative file path
    /// absolute against <paramref name="baseDirectory"/> (not the current directory).
    /// </summary>
    public static string ResolveSqliteConnectionString(string? configured, string baseDirectory)
    {
        var builder = new SqliteConnectionStringBuilder(
            string.IsNullOrWhiteSpace(configured) ? $"Data Source={SettingsStorageOptions.DefaultSqliteFileName}" : configured);

        var dataSource = builder.DataSource;
        var inMemory = builder.Mode == SqliteOpenMode.Memory
            || string.Equals(dataSource, ":memory:", StringComparison.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(dataSource))
            builder.DataSource = Path.Combine(baseDirectory, SettingsStorageOptions.DefaultSqliteFileName);
        else if (!inMemory && !dataSource.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
            builder.DataSource = SettingsStorageOptions.ResolvePath(dataSource, baseDirectory);

        return builder.ToString();
    }
}
