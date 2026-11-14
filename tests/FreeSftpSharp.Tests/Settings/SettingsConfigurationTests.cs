using FxSsh.SshServerModule;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.Database;
using SshServer.Settings.PostgreSql;
using SshServer.Settings.SqlServer;

namespace FreeSftpSharp.Tests.Settings;

/// <summary>Selection of the settings provider and the database location from the configuration.</summary>
public sealed class SettingsConfigurationTests : IDisposable
{
    private readonly TempDirectory _temp = new();

    public void Dispose() => _temp.Dispose();

    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
            .Build();

    private static string Resolve(SettingsStorageOptions options, string baseDirectory)
        => new SqliteSettingsDatabaseProvider().ResolveConnectionString(options.ConfiguredConnectionString, baseDirectory);

    private static string DataSource(string connectionString) => new SqliteConnectionStringBuilder(connectionString).DataSource;

    [Fact]
    public void Without_configuration_the_provider_is_SQLite_with_freesftpsharp_db_in_the_app_directory()
    {
        var options = SettingsStorageOptions.FromConfiguration(Config(), _temp.Path);

        Assert.Equal("Sqlite", options.Provider);
        Assert.False(options.IsLiteDb);
        Assert.Equal(Path.Combine(_temp.Path, "freesftpsharp.db"), DataSource(Resolve(options, _temp.Path)));
        Assert.Equal("config.db", Path.GetFileName(options.LiteDbPath));
    }

    [Fact]
    public void A_relative_SQLite_path_is_relative_to_the_app_directory_not_the_current_directory()
    {
        var options = SettingsStorageOptions.FromConfiguration(
            Config(("ConnectionStrings:Settings", "Data Source=data/settings.db")), _temp.Path);

        Assert.Equal(Path.Combine(_temp.Path, "data", "settings.db"), DataSource(Resolve(options, _temp.Path)));
    }

    [Fact]
    public void An_absolute_SQLite_path_and_an_in_memory_database_are_kept()
    {
        var absolute = _temp.File("abs.db");

        Assert.Equal(absolute, DataSource(Resolve(SettingsStorageOptions.FromConfiguration(
            Config(("ConnectionStrings:Settings", $"Data Source={absolute}")), "/somewhere/else"), "/somewhere/else")));
        Assert.Equal(":memory:", DataSource(Resolve(SettingsStorageOptions.FromConfiguration(
            Config(("ConnectionStrings:Settings", "Data Source=:memory:")), _temp.Path), _temp.Path)));
    }

    [Theory]
    [InlineData("LiteDb")]
    [InlineData("litedb")]
    public void The_LiteDb_provider_can_be_selected(string value)
    {
        var options = SettingsStorageOptions.FromConfiguration(
            Config(("Settings:Provider", value), ("Settings:LiteDbPath", "old.db")), _temp.Path);

        Assert.True(options.IsLiteDb);
        Assert.Equal(_temp.File("old.db"), options.LiteDbPath);
    }

    [Fact]
    public void An_unknown_provider_is_an_error()
    {
        using var services = new ServiceCollection()
            .AddLogging()
            .AddSshServerSettings(Config(("Settings:Provider", "Oracle")))
            .BuildServiceProvider();

        var error = Assert.Throws<InvalidOperationException>(() => services.GetRequiredService<ISettingsRepository>());
        Assert.Contains("Oracle", error.Message);
        Assert.Contains("PostgreSQL", error.Message); // tells how to get the other providers
    }

    [Fact]
    public void AddSshServerSettings_registers_the_SQLite_repository_by_default()
    {
        using var services = new ServiceCollection()
            .AddLogging()
            .AddSshServerSettings(Config(
                ("ConnectionStrings:Settings", _temp.SqliteConnectionString()),
                ("Settings:LiteDbPath", _temp.File("config.db"))))
            .BuildServiceProvider();

        var repository = services.GetRequiredService<ISettingsRepository>();

        Assert.IsType<SqlSettingsRepository>(repository);
        Assert.False(string.IsNullOrEmpty(repository.ServerSettings.ServerRsaKey));
        Assert.True(File.Exists(_temp.File("freesftpsharp.db")));
        Assert.False(File.Exists(_temp.File("config.db")));
    }

    [Fact]
    public void AddSshServerSettings_registers_the_LiteDB_repository_when_configured()
    {
        using var services = new ServiceCollection()
            .AddLogging()
            .AddSshServerSettings(Config(("Settings:Provider", "LiteDb"), ("Settings:LiteDbPath", _temp.File("config.db"))))
            .BuildServiceProvider();

        var repository = services.GetRequiredService<ISettingsRepository>();

        Assert.IsType<SettingsRepository>(repository);
        Assert.True(File.Exists(_temp.File("config.db")));
        Assert.False(File.Exists(_temp.File("freesftpsharp.db")));
        repository.Dispose();
    }

    [Theory]
    [InlineData("PostgreSQL", "Host=db;Database=freesftpsharp", "Npgsql.EntityFrameworkCore.PostgreSQL")]
    [InlineData("postgresql", "Host=db;Database=freesftpsharp", "Npgsql.EntityFrameworkCore.PostgreSQL")]
    [InlineData("SqlServer", "Server=db;Database=freesftpsharp", "Microsoft.EntityFrameworkCore.SqlServer")]
    public void A_registered_database_provider_is_selected_by_its_name(string name, string connectionString, string efProvider)
    {
        using var services = new ServiceCollection()
            .AddLogging()
            .AddSshServerSettings(Config(("Settings:Provider", name), ("ConnectionStrings:Settings", connectionString)))
            .AddPostgreSqlSettings()
            .AddSqlServerSettings()
            .BuildServiceProvider();

        var database = services.GetRequiredService<SettingsDatabase>();

        using var context = new SshServer.Settings.Sql.SettingsDbContext(database.Options);
        Assert.Equal(efProvider, context.Database.ProviderName);
    }

    [Fact]
    public void A_server_database_without_a_connection_string_is_an_error()
    {
        using var services = new ServiceCollection()
            .AddLogging()
            .AddSshServerSettings(Config(("Settings:Provider", "PostgreSQL")))
            .AddPostgreSqlSettings()
            .BuildServiceProvider();

        var error = Assert.Throws<InvalidOperationException>(() => services.GetRequiredService<SettingsDatabase>());
        Assert.Contains("ConnectionStrings:Settings", error.Message);
    }
}
