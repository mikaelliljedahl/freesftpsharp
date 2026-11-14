using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SshServer.Settings.PostgreSql;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.Database;
using SshServer.Settings.SqlServer;

namespace FreeSftpSharp.Tests.Settings.Providers;

/// <summary>
/// A new, empty settings database of one provider for one test, removed on dispose. SQLite is a file in a temp
/// directory; PostgreSQL and SQL Server are a new database on the server of <see cref="PostgreSqlVariable"/> or
/// <see cref="SqlServerVariable"/> (a connection string with a user that may create databases). Without the variable the
/// test is skipped. CI sets both on Linux (service containers).
/// </summary>
public abstract class TestDatabase : IAsyncDisposable
{
    public const string PostgreSqlVariable = "FREESFTPSHARP_TEST_POSTGRES";
    public const string SqlServerVariable = "FREESFTPSHARP_TEST_SQLSERVER";

    public static readonly TheoryData<string> Providers = new(
        SqliteSettingsDatabaseProvider.ProviderName, PostgreSqlSettingsDatabaseProvider.ProviderName, SqlServerSettingsDatabaseProvider.ProviderName);

    protected TestDatabase(ISettingsDatabaseProvider provider, string connectionString)
    {
        Provider = provider;
        ConnectionString = connectionString;
        var builder = new DbContextOptionsBuilder<SettingsDbContext>();
        provider.Configure(builder, connectionString);
        Options = builder.Options;
    }

    public ISettingsDatabaseProvider Provider { get; }

    /// <summary>The value of <c>Settings:Provider</c>.</summary>
    public string ProviderName => Provider.Name;

    /// <summary>The value of <c>ConnectionStrings:Settings</c>.</summary>
    public string ConnectionString { get; }

    public DbContextOptions<SettingsDbContext> Options { get; }

    /// <summary>The configuration keys that select this database, for a host.</summary>
    public IEnumerable<KeyValuePair<string, string?>> Configuration =>
    [
        new(SettingsStorageOptions.ProviderKey, ProviderName),
        new("ConnectionStrings:" + SettingsStorageOptions.ConnectionStringName, ConnectionString),
    ];

    /// <summary>A new database of <paramref name="provider"/>; skips the test when its server is not configured.</summary>
    public static async Task<TestDatabase> CreateAsync(string provider)
    {
        switch (provider)
        {
            case SqliteSettingsDatabaseProvider.ProviderName:
                return new SqliteTestDatabase();
            case PostgreSqlSettingsDatabaseProvider.ProviderName:
                return await PostgreSqlTestDatabase.CreateOnServerAsync(Server(PostgreSqlVariable));
            case SqlServerSettingsDatabaseProvider.ProviderName:
                return await SqlServerTestDatabase.CreateOnServerAsync(Server(SqlServerVariable));
            default:
                throw new ArgumentOutOfRangeException(nameof(provider), provider, null);
        }
    }

    private static string Server(string variable)
    {
        var value = Environment.GetEnvironmentVariable(variable);
        if (string.IsNullOrWhiteSpace(value))
            Assert.Skip($"{variable} is not set (a connection string of a database server is needed).");
        return value;
    }

    protected static string NewDatabaseName() => "fss_test_" + Guid.NewGuid().ToString("N")[..16];

    public abstract ValueTask DisposeAsync();
}

internal sealed class SqliteTestDatabase : TestDatabase
{
    private readonly TempDirectory _directory;

    public SqliteTestDatabase() : this(new TempDirectory())
    {
    }

    private SqliteTestDatabase(TempDirectory directory) : base(new SqliteSettingsDatabaseProvider(), directory.SqliteConnectionString())
    {
        _directory = directory;
    }

    public override ValueTask DisposeAsync()
    {
        _directory.Dispose();
        return ValueTask.CompletedTask;
    }
}

internal sealed class PostgreSqlTestDatabase : TestDatabase
{
    private readonly string _server;
    private readonly string _name;

    private PostgreSqlTestDatabase(string server, string name, string connectionString)
        : base(new PostgreSqlSettingsDatabaseProvider(), connectionString)
    {
        _server = server;
        _name = name;
    }

    public static async Task<TestDatabase> CreateOnServerAsync(string server)
    {
        var name = NewDatabaseName();
        await using (var connection = new NpgsqlConnection(server))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", connection);
            await command.ExecuteNonQueryAsync();
        }
        var builder = new NpgsqlConnectionStringBuilder(server) { Database = name, Pooling = false };
        return new PostgreSqlTestDatabase(server, name, builder.ConnectionString);
    }

    public override async ValueTask DisposeAsync()
    {
        await using var connection = new NpgsqlConnection(_server);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{_name}\" WITH (FORCE)", connection);
        await command.ExecuteNonQueryAsync();
    }
}

internal sealed class SqlServerTestDatabase : TestDatabase
{
    private readonly string _server;
    private readonly string _name;

    private SqlServerTestDatabase(string server, string name, string connectionString)
        : base(new SqlServerSettingsDatabaseProvider(), connectionString)
    {
        _server = server;
        _name = name;
    }

    public static async Task<TestDatabase> CreateOnServerAsync(string server)
    {
        var name = NewDatabaseName();
        await using (var connection = new SqlConnection(server))
        {
            await connection.OpenAsync();
            await using var command = new SqlCommand($"CREATE DATABASE [{name}]", connection);
            await command.ExecuteNonQueryAsync();
        }
        var builder = new SqlConnectionStringBuilder(server) { InitialCatalog = name, Pooling = false };
        return new SqlServerTestDatabase(server, name, builder.ConnectionString);
    }

    public override async ValueTask DisposeAsync()
    {
        await using var connection = new SqlConnection(_server);
        await connection.OpenAsync();
        await using var command = new SqlCommand(
            $"IF DB_ID('{_name}') IS NOT NULL BEGIN ALTER DATABASE [{_name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{_name}]; END",
            connection);
        await command.ExecuteNonQueryAsync();
    }
}
