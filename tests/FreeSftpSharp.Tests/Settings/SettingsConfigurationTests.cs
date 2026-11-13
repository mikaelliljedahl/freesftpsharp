using FxSsh.SshServerModule;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;
using SshServer.Settings.Sql;

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

    private static string DataSource(string connectionString) => new SqliteConnectionStringBuilder(connectionString).DataSource;

    [Fact]
    public void Without_configuration_the_provider_is_SQLite_with_freesftpsharp_db_in_the_app_directory()
    {
        var options = SettingsStorageOptions.FromConfiguration(Config(), _temp.Path);

        Assert.Equal(SettingsProvider.Sqlite, options.Provider);
        Assert.Equal(Path.Combine(_temp.Path, "freesftpsharp.db"), DataSource(options.ConnectionString));
        Assert.Equal("config.db", Path.GetFileName(options.LiteDbPath));
    }

    [Fact]
    public void A_relative_SQLite_path_is_relative_to_the_app_directory_not_the_current_directory()
    {
        var options = SettingsStorageOptions.FromConfiguration(
            Config(("ConnectionStrings:Settings", "Data Source=data/settings.db")), _temp.Path);

        Assert.Equal(Path.Combine(_temp.Path, "data", "settings.db"), DataSource(options.ConnectionString));
    }

    [Fact]
    public void An_absolute_SQLite_path_and_an_in_memory_database_are_kept()
    {
        var absolute = _temp.File("abs.db");

        Assert.Equal(absolute, DataSource(SettingsStorageOptions.FromConfiguration(
            Config(("ConnectionStrings:Settings", $"Data Source={absolute}")), "/somewhere/else").ConnectionString));
        Assert.Equal(":memory:", DataSource(SettingsStorageOptions.FromConfiguration(
            Config(("ConnectionStrings:Settings", "Data Source=:memory:")), _temp.Path).ConnectionString));
    }

    [Theory]
    [InlineData("LiteDb")]
    [InlineData("litedb")]
    public void The_LiteDb_provider_can_be_selected(string value)
    {
        var options = SettingsStorageOptions.FromConfiguration(
            Config(("Settings:Provider", value), ("Settings:LiteDbPath", "old.db")), _temp.Path);

        Assert.Equal(SettingsProvider.LiteDb, options.Provider);
        Assert.Equal(_temp.File("old.db"), options.LiteDbPath);
    }

    [Fact]
    public void An_unknown_provider_is_an_error()
    {
        var error = Assert.Throws<InvalidOperationException>(() =>
            SettingsStorageOptions.FromConfiguration(Config(("Settings:Provider", "Oracle")), _temp.Path));
        Assert.Contains("Oracle", error.Message);
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
}
