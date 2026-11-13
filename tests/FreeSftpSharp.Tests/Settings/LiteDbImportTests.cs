using System.Security.Cryptography;
using FreeSftpSharp.Tests.Infrastructure;
using FxSsh.SshServerModule;
using Microsoft.EntityFrameworkCore;
using SshServer.Interfaces;
using SshServer.Settings.Sql;

namespace FreeSftpSharp.Tests.Settings;

/// <summary>
/// The one-time import of an old LiteDB config.db into a new SQLite settings database. The LiteDB file is made
/// with the old LiteDB SettingsRepository.
/// </summary>
public sealed class LiteDbImportTests : IDisposable
{
    private readonly TempDirectory _temp = new();

    public void Dispose() => _temp.Dispose();

    private string LiteDbPath => _temp.File("config.db");

    private DbContextOptions<SettingsDbContext> SqliteOptions =>
        new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(_temp.SqliteConnectionString()).Options;

    /// <summary>Makes a config.db like an old installation: settings with a host key and two users.</summary>
    private string CreateLiteDb()
    {
        using var liteDb = new SettingsRepository(LiteDbPath);
        ISettingsRepository repository = liteDb;

        var settings = repository.ServerSettings;
        settings.ListenToPort = 2022;
        settings.IdleTimeout = 120;
        settings.BindToAddress = new List<string> { "127.0.0.1" };
        settings.BlacklistedIps = new List<string> { "6.6.6.6" };
        settings.MaxLoginAttemptsBeforeBan = 3;
        settings.EnableDirectTcpIp = true;
        repository.UpdateServerSettings(settings);

        repository.AddUser(new User
        {
            Username = "alice",
            UserRootDirectory = "/srv/alice",
            HashedPassword = TestCredentials.LegacySha256Hash("pw"),
            OnlyWhitelistedIps = true,
            WhitelistedIps = new List<string> { "10.1.2.3" },
            LastSuccessfulLogin = new DateTime(2025, 12, 24, 18, 0, 0, DateTimeKind.Utc),
        });
        repository.AddUser(new User
        {
            Username = "bob",
            UserRootDirectory = "/srv/bob",
            RsaPublicKey = "bob-public-key",
            WhitelistedIps = new List<string>(),
        });

        return repository.ServerSettings.ServerRsaKey;
    }

    private string HashOfLiteDbFile() => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(LiteDbPath)));

    [Fact]
    public void A_new_SQLite_database_imports_settings_host_key_and_users_from_config_db()
    {
        var hostKey = CreateLiteDb();

        using var repository = new SqlSettingsRepository(SqliteOptions, legacyLiteDbPath: LiteDbPath,
            createHostKey: () => throw new InvalidOperationException("The host key must be imported, not created."));

        var settings = repository.ServerSettings;
        Assert.Equal(hostKey, settings.ServerRsaKey);
        Assert.Equal(2022, settings.ListenToPort);
        Assert.Equal(120, settings.IdleTimeout);
        Assert.Equal(new[] { "127.0.0.1" }, settings.BindToAddress);
        Assert.Equal(new[] { "6.6.6.6" }, settings.BlacklistedIps);
        Assert.Equal(3, settings.MaxLoginAttemptsBeforeBan);
        Assert.True(settings.EnableDirectTcpIp);
        Assert.False(settings.EnableCommand);

        Assert.Equal(new[] { "alice", "bob" }, repository.GetAllUsers().Select(u => u.Username).OrderBy(n => n));
        var alice = repository.GetUser("alice");
        Assert.Equal("/srv/alice", alice.UserRootDirectory);
        Assert.Equal(TestCredentials.LegacySha256Hash("pw"), alice.HashedPassword);
        Assert.True(alice.OnlyWhitelistedIps);
        Assert.Equal(new[] { "10.1.2.3" }, alice.WhitelistedIps);
        Assert.Equal(new DateTime(2025, 12, 24, 18, 0, 0, DateTimeKind.Utc), alice.LastSuccessfulLogin.ToUniversalTime());
        var bob = repository.GetUser("bob");
        Assert.Equal("bob-public-key", bob.RsaPublicKey);
        Assert.Null(bob.HashedPassword);
    }

    [Fact]
    public void The_import_does_not_change_config_db()
    {
        CreateLiteDb();
        var before = HashOfLiteDbFile();
        var filesBefore = Directory.GetFiles(_temp.Path).Select(Path.GetFileName).OrderBy(n => n).ToArray();

        using (new SqlSettingsRepository(SqliteOptions, legacyLiteDbPath: LiteDbPath))
        {
        }

        Assert.Equal(before, HashOfLiteDbFile());
        var filesAfter = Directory.GetFiles(_temp.Path).Select(Path.GetFileName).OrderBy(n => n).ToArray();
        Assert.Equal(filesBefore.Append("freesftpsharp.db").OrderBy(n => n), filesAfter);
    }

    [Fact]
    public void An_existing_SQLite_database_does_not_import_again()
    {
        using (var first = new SqlSettingsRepository(SqliteOptions, legacyLiteDbPath: LiteDbPath, createHostKey: () => "sqlite-key"))
        {
            Assert.Empty(first.GetAllUsers());
        }

        CreateLiteDb();

        using var second = new SqlSettingsRepository(SqliteOptions, legacyLiteDbPath: LiteDbPath);
        Assert.Equal("sqlite-key", second.ServerSettings.ServerRsaKey);
        Assert.Empty(second.GetAllUsers());
    }

    [Fact]
    public void Without_config_db_a_new_database_gets_new_default_settings()
    {
        using var repository = new SqlSettingsRepository(SqliteOptions, legacyLiteDbPath: LiteDbPath, createHostKey: () => "new-key");

        Assert.Equal("new-key", repository.ServerSettings.ServerRsaKey);
        Assert.Equal(22, repository.ServerSettings.ListenToPort);
        Assert.False(File.Exists(LiteDbPath));
    }
}
