using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using SshServer.Interfaces;
using SshServer.Interfaces.Permissions;
using SshServer.Settings.Sql;

namespace FreeSftpSharp.Tests.Settings;

/// <summary>
/// CRUD of the EF Core / SQLite settings repository on an in-memory SQLite database (the open connection keeps
/// the database alive), plus persistence in a file.
/// </summary>
public sealed class SqlSettingsRepositoryTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly SqlSettingsRepository _repository;

    public SqlSettingsRepositoryTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _repository = CreateRepository(_connection);
    }

    private static SqlSettingsRepository CreateRepository(SqliteConnection connection, string? hostKey = null)
    {
        var options = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(connection).Options;
        return new SqlSettingsRepository(options, createHostKey: () => hostKey ?? TestCredentials.HostKey);
    }

    public void Dispose()
    {
        _repository.Dispose();
        _connection.Dispose();
    }

    private static User NewUser(string username) => new()
    {
        Username = username,
        UserRootDirectory = "/srv/sftp/" + username,
        HashedPassword = TestCredentials.HashPassword("secret"),
        RsaPublicKey = null!,
        OnlyWhitelistedIps = true,
        WhitelistedIps = new List<string> { "10.0.0.0/8", "192.168.1.5" },
        LastSuccessfulLogin = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc),
    };

    [Fact]
    public void A_new_database_gets_default_settings_with_a_host_key_and_port_22()
    {
        var settings = _repository.ServerSettings;

        Assert.Equal(TestCredentials.HostKey, settings.ServerRsaKey);
        Assert.Equal(22, settings.ListenToPort);
        Assert.Empty(_repository.GetAllUsers());
    }

    [Fact]
    public void Updated_server_settings_are_stored()
    {
        var settings = _repository.ServerSettings;
        settings.ListenToPort = 2222;
        settings.ServerBanner = "banner";
        settings.BindToAddress = new List<string> { "0.0.0.0", "::" };
        settings.BlacklistedIps = new List<string> { "1.2.3.4" };
        settings.OnlyWhitelistedIps = true;
        settings.WhitelistedIps = new List<string> { "10.0.0.0/8", "2001:db8::/32" };
        settings.MaxLoginAttemptsBeforeBan = 7;
        settings.LoginFailureWindowSeconds = 60;
        settings.BanDurationSeconds = 90;
        settings.ExemptLoopbackFromBan = false;
        settings.IdleTimeout = 300;
        settings.EnableCommand = true;
        settings.EnableDirectTcpIp = true;

        Assert.True(_repository.UpdateServerSettings(settings));

        var stored = _repository.ServerSettings;
        Assert.Equal(TestCredentials.HostKey, stored.ServerRsaKey);
        Assert.Equal(2222, stored.ListenToPort);
        Assert.Equal("banner", stored.ServerBanner);
        Assert.Equal(new[] { "0.0.0.0", "::" }, stored.BindToAddress);
        Assert.Equal(new[] { "1.2.3.4" }, stored.BlacklistedIps);
        Assert.True(stored.OnlyWhitelistedIps);
        Assert.Equal(new[] { "10.0.0.0/8", "2001:db8::/32" }, stored.WhitelistedIps);
        Assert.Equal(7, stored.MaxLoginAttemptsBeforeBan);
        Assert.Equal(60, stored.LoginFailureWindowSeconds);
        Assert.Equal(90, stored.BanDurationSeconds);
        Assert.False(stored.ExemptLoopbackFromBan);
        Assert.Equal(300, stored.IdleTimeout);
        Assert.True(stored.EnableCommand);
        Assert.True(stored.EnableDirectTcpIp);
    }

    [Fact]
    public void A_new_database_has_the_default_ban_settings()
    {
        var settings = _repository.ServerSettings;

        Assert.Equal(5, settings.MaxLoginAttemptsBeforeBan);
        Assert.Equal(600, settings.LoginFailureWindowSeconds);
        Assert.Equal(1800, settings.BanDurationSeconds);
        Assert.True(settings.ExemptLoopbackFromBan);
        Assert.False(settings.OnlyWhitelistedIps);
    }

    [Fact]
    public void A_database_of_an_older_version_is_upgraded_and_keeps_its_settings()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        var options = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(connection).Options;
        using (var db = new SettingsDbContext(options))
        {
            // The schema before issue #43, with a settings row as an older version wrote it.
            db.GetService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>().Migrate("20261113220305_AddServerEcdsaKey");
            db.Database.ExecuteSqlRaw(
                "INSERT INTO ServerSettings (ServerRsaKey, ServerBanner, ListenToPort, ServerRootDirectory, BindToAddress, " +
                "BlacklistedIps, MaxLoginAttemptsBeforeBan, IdleTimeout, EnableCommand, EnableDirectTcpIp) " +
                "VALUES ('old-key', 'old-banner', 2022, '/srv', '[\"127.0.0.1\"]', '[\"6.6.6.6\"]', 0, 60, 0, 0)");
        }

        using var repository = new SqlSettingsRepository(options, createHostKey: () => throw new InvalidOperationException("must not be called"));

        var settings = repository.ServerSettings;
        Assert.Equal("old-key", settings.ServerRsaKey);
        Assert.Equal(2022, settings.ListenToPort);
        Assert.Equal(new[] { "127.0.0.1" }, settings.BindToAddress);
        Assert.Equal(new[] { "6.6.6.6" }, settings.BlacklistedIps);
        Assert.Equal(0, settings.MaxLoginAttemptsBeforeBan); // the stored value: auto-ban stays off until it is set
        Assert.Equal(600, settings.LoginFailureWindowSeconds);
        Assert.Equal(1800, settings.BanDurationSeconds);
        Assert.True(settings.ExemptLoopbackFromBan);
        Assert.False(settings.OnlyWhitelistedIps);
        Assert.Null(settings.WhitelistedIps);
    }

    [Fact]
    public void The_ecdsa_host_key_is_stored_and_an_empty_value_does_not_remove_it()
    {
        Assert.Null(_repository.ServerSettings.ServerEcdsaKey); // a new database has none; HostedServer makes it

        var settings = _repository.ServerSettings;
        settings.ServerEcdsaKey = "ecdsa-pem";
        Assert.True(_repository.UpdateServerSettings(settings));
        Assert.Equal("ecdsa-pem", _repository.ServerSettings.ServerEcdsaKey);

        // A caller that does not know the field (for example an older admin page) sends it empty.
        var withoutKey = _repository.ServerSettings;
        withoutKey.ServerEcdsaKey = null!;
        withoutKey.ListenToPort = 2200;
        Assert.True(_repository.UpdateServerSettings(withoutKey));
        Assert.Equal("ecdsa-pem", _repository.ServerSettings.ServerEcdsaKey);
        Assert.Equal(2200, _repository.ServerSettings.ListenToPort);

        var replaced = _repository.ServerSettings;
        replaced.ServerEcdsaKey = "new-ecdsa-pem";
        Assert.True(_repository.UpdateServerSettings(replaced));
        Assert.Equal("new-ecdsa-pem", _repository.ServerSettings.ServerEcdsaKey);
    }

    [Fact]
    public void An_added_user_can_be_read_with_all_fields()
    {
        var user = NewUser("alice");

        Assert.True(_repository.AddUser(user));

        var stored = _repository.GetUser("alice");
        Assert.NotNull(stored);
        Assert.Equal("alice", stored.Username);
        Assert.Equal("/srv/sftp/alice", stored.UserRootDirectory);
        Assert.Equal(user.HashedPassword, stored.HashedPassword);
        Assert.Null(stored.RsaPublicKey);
        Assert.True(stored.OnlyWhitelistedIps);
        Assert.Equal(new[] { "10.0.0.0/8", "192.168.1.5" }, stored.WhitelistedIps);
        Assert.Equal(user.LastSuccessfulLogin, stored.LastSuccessfulLogin);
        Assert.Equal(new[] { "alice" }, _repository.GetAllUsers().Select(u => u.Username));
    }

    [Fact]
    public void A_user_without_whitelist_and_password_can_be_stored()
    {
        Assert.True(_repository.AddUser(new User { Username = "keyonly", RsaPublicKey = "key" }));

        var stored = _repository.GetUser("keyonly");
        Assert.Null(stored.HashedPassword);
        Assert.Null(stored.WhitelistedIps);
        Assert.Equal("key", stored.RsaPublicKey);
    }

    [Fact]
    public void An_updated_user_is_stored()
    {
        _repository.AddUser(NewUser("bob"));
        var user = _repository.GetUser("bob");
        var newHash = TestCredentials.HashPassword("new");
        user.HashedPassword = newHash;
        user.RsaPublicKey = "public-key";
        user.UserRootDirectory = "/other";
        user.OnlyWhitelistedIps = false;
        user.WhitelistedIps = new List<string>();
        user.LastSuccessfulLogin = new DateTime(2026, 5, 6, 7, 8, 9, DateTimeKind.Utc);

        Assert.True(_repository.UpdateUser(user));

        var stored = _repository.GetUser("bob");
        Assert.Equal(newHash, stored.HashedPassword);
        Assert.Equal("public-key", stored.RsaPublicKey);
        Assert.Equal("/other", stored.UserRootDirectory);
        Assert.False(stored.OnlyWhitelistedIps);
        Assert.NotNull(stored.WhitelistedIps);
        Assert.Empty(stored.WhitelistedIps);
        Assert.Equal(user.LastSuccessfulLogin, stored.LastSuccessfulLogin);
    }

    private static Dictionary<string, FilePermissions> SamplePermissions() => new()
    {
        ["/"] = FilePermissions.List | FilePermissions.Download,
        ["/incoming"] = FilePermissions.Upload,
        ["/incoming/sub"] = FilePermissions.All,
    };

    private static Dictionary<string, PathFilter> SampleFilters() => new()
    {
        ["/"] = new PathFilter { DeniedPatterns = ["*.exe"], HiddenPatterns = [".git"] },
        ["/data"] = new PathFilter { AllowedPatterns = ["*.csv", "*.txt"] },
    };

    private static void AssertSamplePermissions(User stored)
    {
        Assert.Equal(SamplePermissions(), stored.Permissions);
        Assert.NotNull(stored.PathFilters);
        Assert.Equal(["/", "/data"], stored.PathFilters.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(["*.exe"], stored.PathFilters["/"].DeniedPatterns);
        Assert.Equal([".git"], stored.PathFilters["/"].HiddenPatterns);
        Assert.Equal(["*.csv", "*.txt"], stored.PathFilters["/data"].AllowedPatterns);
    }

    [Fact]
    public void Permissions_and_path_filters_of_a_user_are_stored()
    {
        var user = NewUser("perms");
        user.Permissions = SamplePermissions();
        user.PathFilters = SampleFilters();

        Assert.True(_repository.AddUser(user));

        AssertSamplePermissions(_repository.GetUser("perms"));
    }

    [Fact]
    public void Updated_permissions_and_path_filters_are_stored()
    {
        _repository.AddUser(NewUser("perms2"));
        var user = _repository.GetUser("perms2");
        Assert.Equal(new Dictionary<string, FilePermissions> { ["/"] = FilePermissions.All }, user.Permissions);
        Assert.Null(user.PathFilters);

        user.Permissions = SamplePermissions();
        user.PathFilters = SampleFilters();
        Assert.True(_repository.UpdateUser(user));
        AssertSamplePermissions(_repository.GetUser("perms2"));

        // A change inside the same dictionary is seen too.
        user = _repository.GetUser("perms2");
        user.Permissions!["/incoming"] = FilePermissions.None;
        user.PathFilters!.Remove("/data");
        Assert.True(_repository.UpdateUser(user));
        var stored = _repository.GetUser("perms2");
        Assert.Equal(FilePermissions.None, stored.Permissions!["/incoming"]);
        Assert.Equal(["/"], stored.PathFilters!.Keys);
    }

    [Fact]
    public async Task Users_of_a_database_before_per_path_permissions_keep_their_data_and_get_full_access()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        var options = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(connection).Options;
        using (var db = new SettingsDbContext(options))
        {
            // The schema before issue #59, with a user row as an older version wrote it.
            db.GetService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>().Migrate("20261113221412_AddIpFilterAndBanSettings");
            db.Database.ExecuteSqlRaw(
                "INSERT INTO ServerSettings (ServerRsaKey, ServerBanner, ListenToPort, BindToAddress, BlacklistedIps, MaxLoginAttemptsBeforeBan, " +
                "IdleTimeout, EnableCommand, EnableDirectTcpIp, OnlyWhitelistedIps, LoginFailureWindowSeconds, BanDurationSeconds, ExemptLoopbackFromBan) " +
                "VALUES ('old-key', NULL, 22, NULL, NULL, 0, 600, 0, 0, 0, 600, 1800, 1)");
            db.Database.ExecuteSqlRaw(
                "INSERT INTO Users (Username, UserRootDirectory, HashedPassword, RsaPublicKey, OnlyWhitelistedIps, WhitelistedIps, LastSuccessfulLogin) " +
                "VALUES ('old', '/srv/old', 'hash', 'key', 1, '[\"10.0.0.0/8\"]', '2026-01-02 03:04:05')");
        }

        using var repository = new SqlSettingsRepository(options, createHostKey: () => throw new InvalidOperationException("must not be called"));

        var user = repository.GetUser("old");
        Assert.Equal("/srv/old", user.UserRootDirectory);
        Assert.Equal("hash", user.HashedPassword);
        Assert.Equal("key", user.RsaPublicKey);
        Assert.Equal(new[] { "10.0.0.0/8" }, user.WhitelistedIps);
        Assert.Equal(new Dictionary<string, FilePermissions> { ["/"] = FilePermissions.All }, user.Permissions);
        Assert.Null(user.PathFilters);
        Assert.True(new EffectivePermissionsService().Resolve(user).IsUnrestricted);

        // The migrated user can get rules like a new one.
        user.Permissions = SamplePermissions();
        Assert.True(repository.UpdateUser(user));
        Assert.Equal(SamplePermissions(), repository.GetUser("old").Permissions);

        // The upgrade also runs the later migrations in order: the audit table (#65) comes after the permissions, and
        // the storage and virtual folders (#56) after it.
        using (var db = new SettingsDbContext(options))
            Assert.Equal(["20261114080103_AddUserPermissions", "20261114082326_AddAuditLog", "20261114105828_AddUserStorageAndVirtualFolders"],
                db.Database.GetAppliedMigrations().TakeLast(3));
        var audit = new SshServer.Settings.Sql.Audit.SqlAuditLog(options);
        await audit.AppendAsync(new SshServer.Interfaces.Audit.AuditEntry { Category = "File", Type = "Upload", Status = "Ok", Username = "old" },
            TestContext.Current.CancellationToken);
        Assert.Equal(1, (await audit.QueryAsync(new SshServer.Interfaces.Audit.AuditQuery { Username = "old" }, TestContext.Current.CancellationToken)).TotalCount);
    }

    [Fact]
    public void A_removed_user_is_gone()
    {
        _repository.AddUser(NewUser("carol"));
        _repository.AddUser(NewUser("dave"));

        Assert.True(_repository.RemoveUser("carol"));

        Assert.Null(_repository.GetUser("carol"));
        Assert.Equal(new[] { "dave" }, _repository.GetAllUsers().Select(u => u.Username));
    }

    [Fact]
    public void Unknown_users_are_not_found_updated_or_removed()
    {
        Assert.Null(_repository.GetUser("nobody"));
        Assert.False(_repository.UpdateUser(new User { Username = "nobody" }));
        Assert.False(_repository.RemoveUser("nobody"));
    }

    [Fact]
    public void A_duplicate_username_is_rejected_case_insensitively_like_LiteDB()
    {
        Assert.True(_repository.AddUser(NewUser("erin")));

        Assert.False(_repository.AddUser(NewUser("erin")));
        Assert.False(_repository.AddUser(NewUser("ERIN")));
        Assert.Equal("erin", _repository.GetUser("Erin").Username);
        Assert.Single(_repository.GetAllUsers());
    }

    [Fact]
    public void Settings_and_users_survive_a_restart_with_a_database_file()
    {
        using var temp = new TempDirectory();
        var options = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(temp.SqliteConnectionString()).Options;

        using (var first = new SqlSettingsRepository(options, createHostKey: () => "first-key"))
        {
            first.AddUser(NewUser("frank"));
        }

        using var second = new SqlSettingsRepository(options, createHostKey: () => "second-key");

        Assert.Equal("first-key", second.ServerSettings.ServerRsaKey);
        Assert.Equal("/srv/sftp/frank", second.GetUser("frank").UserRootDirectory);
    }
}
