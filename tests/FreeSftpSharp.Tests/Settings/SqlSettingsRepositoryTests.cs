using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SshServer.Interfaces;
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
        settings.ServerRootDirectory = "/srv/sftp";
        settings.BindToAddress = new List<string> { "0.0.0.0", "::" };
        settings.BlacklistedIps = new List<string> { "1.2.3.4" };
        settings.MaxLoginAttemptsBeforeBan = 5;
        settings.IdleTimeout = 300;
        settings.EnableCommand = true;
        settings.EnableDirectTcpIp = true;

        Assert.True(_repository.UpdateServerSettings(settings));

        var stored = _repository.ServerSettings;
        Assert.Equal(TestCredentials.HostKey, stored.ServerRsaKey);
        Assert.Equal(2222, stored.ListenToPort);
        Assert.Equal("banner", stored.ServerBanner);
        Assert.Equal("/srv/sftp", stored.ServerRootDirectory);
        Assert.Equal(new[] { "0.0.0.0", "::" }, stored.BindToAddress);
        Assert.Equal(new[] { "1.2.3.4" }, stored.BlacklistedIps);
        Assert.Equal(5, stored.MaxLoginAttemptsBeforeBan);
        Assert.Equal(300, stored.IdleTimeout);
        Assert.True(stored.EnableCommand);
        Assert.True(stored.EnableDirectTcpIp);
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
        Assert.Empty(stored.WhitelistedIps);
        Assert.Equal(user.LastSuccessfulLogin, stored.LastSuccessfulLogin);
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
