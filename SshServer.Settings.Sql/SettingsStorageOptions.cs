using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;

namespace SshServer.Settings.Sql;

/// <summary>Where the settings and users are stored.</summary>
public enum SettingsProvider
{
    /// <summary>EF Core with SQLite (the default).</summary>
    Sqlite,

    /// <summary>The old LiteDB file. Obsolete, kept for compatibility.</summary>
    LiteDb,
}

/// <summary>
/// The settings storage configuration:
/// <list type="bullet">
/// <item><c>Settings:Provider</c> = <c>Sqlite</c> (default) or <c>LiteDb</c>.</item>
/// <item><c>ConnectionStrings:Settings</c> = the connection string of the SQL database. Default:
/// <c>Data Source=&lt;app directory&gt;/freesftpsharp.db</c>. A relative SQLite path is relative to the app directory.</item>
/// <item><c>Settings:LiteDbPath</c> = the LiteDB file that is used by the LiteDb provider and imported once by the
/// Sqlite provider. Default: <c>config.db</c> in the current directory (where the old versions put it), else in the
/// app directory.</item>
/// </list>
/// </summary>
public sealed class SettingsStorageOptions
{
    public const string ProviderKey = "Settings:Provider";
    public const string ConnectionStringName = "Settings";
    public const string LiteDbPathKey = "Settings:LiteDbPath";
    public const string DefaultSqliteFileName = "freesftpsharp.db";
    public const string LegacyLiteDbFileName = "config.db";

    public SettingsProvider Provider { get; init; } = SettingsProvider.Sqlite;

    /// <summary>The resolved connection string (SQL providers only).</summary>
    public string ConnectionString { get; init; } = "";

    /// <summary>The LiteDB file: the store of the LiteDb provider, the import source of the SQL providers.</summary>
    public string LiteDbPath { get; init; } = "";

    public static SettingsStorageOptions FromConfiguration(IConfiguration configuration, string? baseDirectory = null)
    {
        baseDirectory ??= AppContext.BaseDirectory;

        var providerText = configuration[ProviderKey];
        var provider = SettingsProvider.Sqlite;
        if (!string.IsNullOrWhiteSpace(providerText)
            && !Enum.TryParse(providerText.Trim(), ignoreCase: true, out provider))
        {
            throw new InvalidOperationException(
                $"Unknown {ProviderKey} '{providerText}'. Supported values: {string.Join(", ", Enum.GetNames<SettingsProvider>())}.");
        }

        var configuredLiteDbPath = configuration[LiteDbPathKey];
        string liteDbPath;
        if (!string.IsNullOrWhiteSpace(configuredLiteDbPath))
        {
            liteDbPath = Path.GetFullPath(configuredLiteDbPath, baseDirectory);
        }
        else
        {
            var inCurrentDirectory = Path.GetFullPath(LegacyLiteDbFileName);
            var inBaseDirectory = Path.Combine(baseDirectory, LegacyLiteDbFileName);
            liteDbPath = File.Exists(inCurrentDirectory) || !File.Exists(inBaseDirectory)
                ? inCurrentDirectory
                : inBaseDirectory;
        }

        var connectionString = provider switch
        {
            SettingsProvider.Sqlite => ResolveSqliteConnectionString(configuration.GetConnectionString(ConnectionStringName), baseDirectory),
            _ => "",
        };

        return new SettingsStorageOptions
        {
            Provider = provider,
            ConnectionString = connectionString,
            LiteDbPath = liteDbPath,
        };
    }

    /// <summary>
    /// Uses the default file next to the app when nothing is configured, and makes a relative file path
    /// absolute against <paramref name="baseDirectory"/> (not the current directory).
    /// </summary>
    public static string ResolveSqliteConnectionString(string? configured, string baseDirectory)
    {
        var builder = new SqliteConnectionStringBuilder(
            string.IsNullOrWhiteSpace(configured) ? $"Data Source={DefaultSqliteFileName}" : configured);

        var dataSource = builder.DataSource;
        var inMemory = builder.Mode == SqliteOpenMode.Memory
            || string.Equals(dataSource, ":memory:", StringComparison.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(dataSource))
            builder.DataSource = Path.Combine(baseDirectory, DefaultSqliteFileName);
        else if (!inMemory && !dataSource.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
            builder.DataSource = Path.GetFullPath(dataSource, baseDirectory);

        return builder.ToString();
    }
}
