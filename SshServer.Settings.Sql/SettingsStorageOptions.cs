using Microsoft.Extensions.Configuration;
using SshServer.Settings.Sql.Database;

namespace SshServer.Settings.Sql;

/// <summary>
/// The settings storage configuration:
/// <list type="bullet">
/// <item><c>Settings:Provider</c> = <c>Sqlite</c> (default), <c>PostgreSQL</c>, <c>SqlServer</c> (an
/// <see cref="ISettingsDatabaseProvider"/>) or <c>LiteDb</c> (the old file, obsolete).</item>
/// <item><c>ConnectionStrings:Settings</c> = the connection string of the SQL database. SQLite default:
/// <c>Data Source=&lt;app directory&gt;/freesftpsharp.db</c>; a relative SQLite path is relative to the app directory.
/// PostgreSQL and SQL Server need it.</item>
/// <item><c>Settings:LiteDbPath</c> = the LiteDB file that is used by the LiteDb provider and imported once by a SQL
/// provider. Default: <c>config.db</c> in the current directory (where the old versions put it), else in the
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

    /// <summary>The value of <c>Settings:Provider</c> for the old LiteDB file.</summary>
    public const string LiteDbProviderName = "LiteDb";

    /// <summary>The configured provider name (<c>Settings:Provider</c>); default <c>Sqlite</c>.</summary>
    public string Provider { get; init; } = SqliteSettingsDatabaseProvider.ProviderName;

    /// <summary>True for the old LiteDB file, which is not an EF Core provider.</summary>
    public bool IsLiteDb => string.Equals(Provider, LiteDbProviderName, StringComparison.OrdinalIgnoreCase);

    /// <summary>The configured connection string (<c>ConnectionStrings:Settings</c>), or null. The provider resolves it.</summary>
    public string? ConfiguredConnectionString { get; init; }

    /// <summary>The LiteDB file: the store of the LiteDb provider, the import source of the SQL providers.</summary>
    public string LiteDbPath { get; init; } = "";

    public static SettingsStorageOptions FromConfiguration(IConfiguration configuration, string? baseDirectory = null)
    {
        baseDirectory ??= AppContext.BaseDirectory;

        var providerText = configuration[ProviderKey];
        var provider = string.IsNullOrWhiteSpace(providerText) ? SqliteSettingsDatabaseProvider.ProviderName : providerText.Trim();

        var configuredLiteDbPath = configuration[LiteDbPathKey];
        string liteDbPath;
        if (!string.IsNullOrWhiteSpace(configuredLiteDbPath))
        {
            liteDbPath = ResolvePath(configuredLiteDbPath, baseDirectory);
        }
        else
        {
            var inCurrentDirectory = Path.GetFullPath(LegacyLiteDbFileName);
            var inBaseDirectory = Path.Combine(baseDirectory, LegacyLiteDbFileName);
            liteDbPath = File.Exists(inCurrentDirectory) || !File.Exists(inBaseDirectory)
                ? inCurrentDirectory
                : inBaseDirectory;
        }

        return new SettingsStorageOptions
        {
            Provider = provider,
            ConfiguredConnectionString = configuration.GetConnectionString(ConnectionStringName),
            LiteDbPath = liteDbPath,
        };
    }

    // A fully qualified path is kept as it is. Path.GetFullPath(path, basePath) throws
    // when basePath is not fully qualified, also when path itself is absolute.
    internal static string ResolvePath(string path, string baseDirectory)
    {
        return Path.IsPathFullyQualified(path) ? Path.GetFullPath(path) : Path.GetFullPath(path, baseDirectory);
    }
}
