using SshServer.Interfaces.Users;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings.Providers;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Permissions;
using SshServer.Settings.Sql;

namespace FreeSftpSharp.Tests.Settings;

/// <summary>
/// CRUD of the EF Core settings repository on a new database of the provider of the run (<see cref="TestDatabase.CreateDefault"/>:
/// SQLite, or PostgreSQL / SQL Server with <c>FREESFTPSHARP_TEST_DB</c>), plus persistence over a restart. The upgrades of
/// old SQLite schemas stay on SQLite (they test its migrations).
/// </summary>
public sealed class SqlSettingsRepositoryTests : IDisposable
{
    private readonly TestDatabase _database;
    private readonly SqlSettingsRepository _repository;

    public SqlSettingsRepositoryTests()
    {
        _database = TestDatabase.CreateDefault();
        _repository = _database.Repository();
    }

    public void Dispose()
    {
        _repository.Dispose();
        _database.Dispose();
    }

    private static User NewUser(string username) => new()
    {
        Username = username,
        UserRootDirectory = "/srv/sftp/" + username,
        HashedPassword = TestCredentials.HashPassword("secret"),
        OnlyWhitelistedIps = true,
        WhitelistedIps = new List<string> { "10.0.0.0/8", "192.168.1.5" },
        LastLoginAt = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc),
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
        Assert.Null(stored.PublicKeys);
        Assert.Equal(AuthMethods.All, stored.AllowedAuthMethods);
        Assert.Null(stored.RequireAllOf);
        Assert.True(stored.OnlyWhitelistedIps);
        Assert.Equal(new[] { "10.0.0.0/8", "192.168.1.5" }, stored.WhitelistedIps);
        Assert.Equal(user.LastLoginAt, stored.LastLoginAt);
        Assert.Equal(new[] { "alice" }, _repository.GetAllUsers().Select(u => u.Username));
    }

    [Fact]
    public void A_user_without_whitelist_and_password_can_be_stored()
    {
        var key = TestUserKeys.Ed25519();
        Assert.True(_repository.AddUser(new User { Username = "keyonly", PublicKeys = [key.Entry] }));

        var stored = _repository.GetUser("keyonly");
        Assert.Null(stored.HashedPassword);
        Assert.Null(stored.WhitelistedIps);
        Assert.Equal(key.Entry.KeyBase64, Assert.Single(stored.PublicKeys!).KeyBase64);
    }

    [Fact]
    public void An_updated_user_is_stored()
    {
        _repository.AddUser(NewUser("bob"));
        var user = _repository.GetUser("bob");
        var newHash = TestCredentials.HashPassword("new");
        user.HashedPassword = newHash;
        var key = TestUserKeys.Ed25519();
        user.PublicKeys = [key.Entry];
        user.AllowedAuthMethods = AuthMethods.Password | AuthMethods.PublicKey;
        user.RequireAllOf = [AuthMethods.PublicKey, AuthMethods.Password];
        user.UserRootDirectory = "/other";
        user.OnlyWhitelistedIps = false;
        user.WhitelistedIps = new List<string>();
        user.LastLoginAt = new DateTime(2026, 5, 6, 7, 8, 9, DateTimeKind.Utc);

        Assert.True(_repository.UpdateUser(user));

        var stored = _repository.GetUser("bob");
        Assert.Equal(newHash, stored.HashedPassword);
        Assert.Equal(key.Entry.KeyBase64, Assert.Single(stored.PublicKeys!).KeyBase64);
        Assert.Equal(AuthMethods.Password | AuthMethods.PublicKey, stored.AllowedAuthMethods);
        Assert.Equal([AuthMethods.PublicKey, AuthMethods.Password], stored.RequireAllOf);
        Assert.Equal("/other", stored.UserRootDirectory);
        Assert.False(stored.OnlyWhitelistedIps);
        Assert.NotNull(stored.WhitelistedIps);
        Assert.Empty(stored.WhitelistedIps);
        Assert.Equal(user.LastLoginAt, stored.LastLoginAt);
    }

    [Fact]
    public void The_protocols_and_app_passwords_of_a_user_are_stored()
    {
        _repository.AddUser(NewUser("carol"));
        var user = _repository.GetUser("carol");
        Assert.Equal(UserProtocols.All, user.AllowedProtocols);
        var (entry, secret) = AppPasswordGenerator.Create("Finder", UserProtocols.WebDav, new DateTime(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc),
            new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        user.AllowedProtocols = UserProtocols.WebDav;
        user.AppPasswords = [entry];

        Assert.True(_repository.UpdateUser(user));

        var stored = _repository.GetUser("carol");
        Assert.Equal(UserProtocols.WebDav, stored.AllowedProtocols);
        var app = Assert.Single(stored.AppPasswords!);
        Assert.Equal("Finder", app.Name);
        Assert.Equal(entry.SecretHash, app.SecretHash);
        Assert.Equal(UserProtocols.WebDav, app.Protocols);
        Assert.Equal(new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc), app.ExpiresAt);
        Assert.True(app.Matches(secret));
        Assert.DoesNotContain(secret, app.SecretHash);
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
        // Only "/" = All is the same as no permissions of the user since #61 (so a group can give them): not set any more.
        Assert.Null(user.Permissions);
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
        Assert.Null(user.PublicKeys); // "key" is not a readable key: it did not work before and is dropped
        Assert.Equal(AuthMethods.All, user.AllowedAuthMethods);
        Assert.Equal(UserProtocols.All, user.AllowedProtocols); // #71: a user of an older database keeps SFTP
        Assert.Null(user.AppPasswords);
        Assert.Equal(new[] { "10.0.0.0/8" }, user.WhitelistedIps);
        // Only "/" = All is the same as no permissions of the user since #61 (so a group can give them): not set any more.
        Assert.Null(user.Permissions);
        Assert.Null(user.PathFilters);
        Assert.True(new EffectiveUserSettingsService().Resolve(user).Permissions.IsUnrestricted);

        // The migrated user can get rules like a new one.
        user.Permissions = SamplePermissions();
        Assert.True(repository.UpdateUser(user));
        Assert.Equal(SamplePermissions(), repository.GetUser("old").Permissions);

        // The upgrade also runs the later migrations in order: the audit table (#65) comes right after the permissions.
        // Later migrations can follow; they are not part of this check.
        using (var db = new SettingsDbContext(options))
        {
            var applied = db.Database.GetAppliedMigrations().ToList();
            var permissions = applied.IndexOf("20261114080103_AddUserPermissions");
            Assert.True(permissions >= 0, string.Join(", ", applied));
            Assert.Equal("20261114082326_AddAuditLog", applied.ElementAtOrDefault(permissions + 1));
            Assert.Contains(applied, m => m.EndsWith("_AddUserPublicKeysAndAuthMethods", StringComparison.Ordinal));
        }
        var audit = new SshServer.Settings.Sql.Audit.SqlAuditLog(options);
        await audit.AppendAsync(new SshServer.Interfaces.Audit.AuditEntry { Category = "File", Type = "Upload", Status = "Ok", Username = "old" },
            TestContext.Current.CancellationToken);
        Assert.Equal(1, (await audit.QueryAsync(new SshServer.Interfaces.Audit.AuditQuery { Username = "old" }, TestContext.Current.CancellationToken)).TotalCount);
    }

    [Fact]
    public void Users_of_a_database_before_issue_58_keep_their_key_and_password()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        var options = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(connection).Options;
        using var rsa = new System.Security.Cryptography.RSACryptoServiceProvider(2048);
        var csp = Convert.ToBase64String(rsa.ExportCspBlob(false));
        var hash = TestCredentials.HashPassword("old-password");
        using (var db = new SettingsDbContext(options))
        {
            // The schema before issue #58: one key per user as a base64 CSP blob in the column RsaPublicKey.
            db.GetService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>().Migrate("20261114112133_AddAdminsAndRoles");
            db.Database.ExecuteSqlRaw(
                "INSERT INTO ServerSettings (ServerRsaKey, ServerBanner, ListenToPort, BindToAddress, BlacklistedIps, MaxLoginAttemptsBeforeBan, " +
                "IdleTimeout, EnableCommand, EnableDirectTcpIp, OnlyWhitelistedIps, LoginFailureWindowSeconds, BanDurationSeconds, ExemptLoopbackFromBan) " +
                "VALUES ('old-key', NULL, 22, NULL, NULL, 0, 600, 0, 0, 0, 600, 1800, 1)");
            db.Database.ExecuteSqlRaw(
                "INSERT INTO Users (Username, UserRootDirectory, HashedPassword, RsaPublicKey, OnlyWhitelistedIps, WhitelistedIps, LastSuccessfulLogin, Permissions) " +
                "VALUES ('both', '/srv/both', {0}, {1}, 0, NULL, '2026-01-02 03:04:05', NULL), " +
                "('passwordonly', '/srv/p', {0}, NULL, 0, NULL, '2026-01-02 03:04:05', NULL)", hash, csp);
        }

        using (var repository = new SqlSettingsRepository(options, createHostKey: () => throw new InvalidOperationException("must not be called")))
        {
            var both = repository.GetUser("both");
            var entry = Assert.Single(both.PublicKeys!);
            Assert.Equal("ssh-rsa", entry.KeyType);
            var blob = SshPublicKey.RsaBlob(rsa.ExportParameters(false));
            Assert.Equal(Convert.ToBase64String(blob), entry.KeyBase64);
            Assert.Equal(SshPublicKey.Fingerprint(blob), entry.Fingerprint);
            Assert.Equal(PublicKeySource.Admin, entry.Source);
            Assert.Null(entry.ExpiresAt);
            Assert.Equal(hash, both.HashedPassword);
            Assert.Equal(AuthMethods.All, both.AllowedAuthMethods);
            Assert.Null(both.RequireAllOf);
            Assert.True(FxSsh.SshServerModule.UserLogics.VerifyUserKey(both, blob, DateTime.UtcNow));

            var passwordOnly = repository.GetUser("passwordonly");
            Assert.Null(passwordOnly.PublicKeys);
            Assert.Equal(AuthMethods.All, passwordOnly.AllowedAuthMethods);
        }

        // The old column is cleared, so the next start does not add the key again.
        using (var db = new SettingsDbContext(options))
            Assert.Equal(0, db.Database.SqlQueryRaw<int>("SELECT COUNT(*) AS Value FROM Users WHERE RsaPublicKey IS NOT NULL").Single());
        using (var again = new SqlSettingsRepository(options))
            Assert.Single(again.GetUser("both").PublicKeys!);
    }

    [Fact]
    public void The_keys_of_a_user_are_stored_with_all_fields()
    {
        var key = TestUserKeys.Rsa("bob@laptop");
        key.Entry.ExpiresAt = new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        key.Entry.Source = PublicKeySource.SelfService;
        var user = NewUser("keys");
        user.PublicKeys = [key.Entry, TestUserKeys.Ed25519().Entry];
        Assert.True(_repository.AddUser(user));

        var stored = _repository.GetUser("keys").PublicKeys!;

        Assert.Equal(2, stored.Count);
        Assert.Equal(key.Entry.KeyType, stored[0].KeyType);
        Assert.Equal(key.Entry.KeyBase64, stored[0].KeyBase64);
        Assert.Equal(key.Entry.Fingerprint, stored[0].Fingerprint);
        Assert.Equal("bob@laptop", stored[0].Comment);
        Assert.Equal(key.Entry.AddedAt, stored[0].AddedAt);
        Assert.Equal(key.Entry.ExpiresAt, stored[0].ExpiresAt);
        Assert.Equal(PublicKeySource.SelfService, stored[0].Source);
        Assert.Equal("ssh-ed25519", stored[1].KeyType);
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
        using var database = TestDatabase.CreateDefault();
        var options = database.Options;

        using (var first = new SqlSettingsRepository(options, createHostKey: () => "first-key"))
        {
            first.AddUser(NewUser("frank"));
        }

        using var second = new SqlSettingsRepository(options, createHostKey: () => "second-key");

        Assert.Equal("first-key", second.ServerSettings.ServerRsaKey);
        Assert.Equal("/srv/sftp/frank", second.GetUser("frank").UserRootDirectory);
    }
}
