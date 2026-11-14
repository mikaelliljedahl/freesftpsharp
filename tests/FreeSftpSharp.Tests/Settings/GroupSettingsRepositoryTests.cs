using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.Infrastructure;
using FxSsh.SshServerModule;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using SshServer.Settings.Sql;
using SshServerModule.Events;

namespace FreeSftpSharp.Tests.Settings;

/// <summary>
/// The groups and the lifecycle fields of the users (issue #61) in the SQLite and LiteDB settings stores, and the upgrade
/// of a database from before #61.
/// </summary>
public sealed class GroupSettingsRepositoryTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly RecordingEventSink _sink = new();
    private readonly ChannelEventBus _bus;
    private readonly SqlSettingsRepository _repository;

    public GroupSettingsRepositoryTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _bus = new ChannelEventBus([_sink], [], NullLogger<ChannelEventBus>.Instance);
        _repository = new SqlSettingsRepository(Options(_connection), createHostKey: () => TestCredentials.HostKey, events: _bus);
    }

    public void Dispose()
    {
        _repository.Dispose();
        _bus.DisposeAsync().AsTask().GetAwaiter().GetResult();
        _connection.Dispose();
    }

    private static DbContextOptions<SettingsDbContext> Options(SqliteConnection connection) =>
        new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(connection).Options;

    private VirtualFolder AddFolder(string name)
    {
        var folder = new VirtualFolder { Name = name, Storage = new StorageConfig { Provider = "local", Options = "{\"RootDirectory\":\"/srv/" + name + "\"}" } };
        Assert.True(_repository.AddVirtualFolder(folder));
        return folder;
    }

    private static Group SampleGroup(string name, int folderId) => new()
    {
        Name = name,
        Description = "the sales team",
        Permissions = new() { ["/"] = FilePermissions.List | FilePermissions.Download, ["/in"] = FilePermissions.Upload },
        PathFilters = new() { ["/"] = new PathFilter { DeniedPatterns = ["*.exe"] } },
        Storage = new StorageConfig { Provider = "local", Options = "{\"RootDirectory\":\"/srv/%username%\"}" },
        VirtualFolders = [new VirtualFolderMount { VirtualFolderId = folderId, MountPath = "/shared" }],
        AllowedAuthMethods = AuthMethods.PublicKey,
        AllowedIps = ["10.0.0.0/8"],
    };

    [Fact]
    public async Task A_group_is_saved_read_changed_and_removed_with_events()
    {
        var folder = AddFolder("shared");
        var group = SampleGroup("sales", folder.Id);

        Assert.True(_repository.AddGroup(group));
        Assert.NotEqual(0, group.Id);
        Assert.False(_repository.AddGroup(new Group { Name = "SALES" }));

        var stored = _repository.GetGroup(group.Id)!;
        Assert.Equal("the sales team", stored.Description);
        Assert.Equal(group.Permissions, stored.Permissions);
        Assert.Equal(["*.exe"], stored.PathFilters!["/"].DeniedPatterns);
        Assert.Equal(group.Storage, stored.Storage);
        Assert.Equal([("/shared", folder.Id)], stored.VirtualFolders.Select(m => (m.MountPath, m.VirtualFolderId)));
        Assert.Equal(AuthMethods.PublicKey, stored.AllowedAuthMethods);
        Assert.Equal(["10.0.0.0/8"], stored.AllowedIps);

        stored.Permissions = null;
        stored.AllowedAuthMethods = null;
        stored.VirtualFolders.Clear();
        Assert.True(_repository.UpdateGroup(stored));
        var changed = _repository.GetGroup(group.Id)!;
        Assert.Null(changed.Permissions);
        Assert.Null(changed.AllowedAuthMethods);
        Assert.Empty(changed.VirtualFolders);
        Assert.Equal(["sales"], _repository.GetGroups().Select(g => g.Name));

        Assert.True(_repository.RemoveGroup(group.Id));
        Assert.Null(_repository.GetGroup(group.Id));
        Assert.False(_repository.RemoveGroup(group.Id));

        var events = await _sink.WaitForAsync<ProviderEvent>(e => e.ObjectType == ProviderObjectType.Group, count: 3);
        Assert.Equal([ProviderAction.Add, ProviderAction.Update, ProviderAction.Delete], events.Select(e => e.Action));
        Assert.Contains("Permissions", events[1].ChangedFields);
        Assert.Contains("AllowedAuthMethods", events[1].ChangedFields);
        Assert.IsType<GroupSnapshot>(events[0].Object);
    }

    [Fact]
    public void A_group_with_members_cannot_be_removed()
    {
        var primary = new Group { Name = "primary" };
        var secondary = new Group { Name = "secondary" };
        Assert.True(_repository.AddGroup(primary));
        Assert.True(_repository.AddGroup(secondary));
        Assert.True(_repository.AddUser(new User { Username = "alice", PrimaryGroupId = primary.Id, SecondaryGroupIds = [secondary.Id] }));

        Assert.False(_repository.RemoveGroup(primary.Id));
        Assert.False(_repository.RemoveGroup(secondary.Id));

        var alice = _repository.GetUser("alice");
        alice.PrimaryGroupId = null;
        alice.SecondaryGroupIds = [];
        Assert.True(_repository.UpdateUser(alice));
        Assert.True(_repository.RemoveGroup(primary.Id));
        Assert.True(_repository.RemoveGroup(secondary.Id));
    }

    [Fact]
    public void Removing_a_virtual_folder_unmounts_it_from_the_groups()
    {
        var folder = AddFolder("shared");
        var group = SampleGroup("sales", folder.Id);
        Assert.True(_repository.AddGroup(group));

        Assert.True(_repository.RemoveVirtualFolder(folder.Id));

        Assert.Empty(_repository.GetGroup(group.Id)!.VirtualFolders);
    }

    [Fact]
    public void The_lifecycle_fields_and_the_groups_of_a_user_are_saved()
    {
        var group = new Group { Name = "g" };
        Assert.True(_repository.AddGroup(group));
        var expires = new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var changed = new DateTime(2026, 11, 1, 8, 0, 0, DateTimeKind.Utc);
        var user = new User
        {
            Username = "alice",
            Description = "external",
            Status = UserStatus.Disabled,
            ExpiresAt = expires,
            MaxSessions = 3,
            PasswordChangedAt = changed,
            PrimaryGroupId = group.Id,
            SecondaryGroupIds = [group.Id + 100, group.Id + 50],
        };
        Assert.True(_repository.AddUser(user));

        var stored = _repository.GetUser("alice");
        Assert.Equal(("external", UserStatus.Disabled, expires, 3, changed, group.Id),
            (stored.Description, stored.Status, stored.ExpiresAt!.Value, stored.MaxSessions, stored.PasswordChangedAt!.Value, stored.PrimaryGroupId!.Value));
        Assert.Equal([group.Id + 100, group.Id + 50], stored.SecondaryGroupIds);

        stored.Status = UserStatus.Enabled;
        stored.ExpiresAt = null;
        stored.SecondaryGroupIds = [];
        Assert.True(_repository.UpdateUser(stored));
        var again = _repository.GetUser("alice");
        Assert.Equal(UserStatus.Enabled, again.Status);
        Assert.Null(again.ExpiresAt);
        Assert.Empty(again.SecondaryGroupIds);
    }

    [Fact]
    public void The_maximum_password_age_is_saved()
    {
        var settings = _repository.ServerSettings;
        Assert.Equal(0, settings.PasswordMaxAgeDays);

        settings.PasswordMaxAgeDays = 90;
        Assert.True(_repository.UpdateServerSettings(settings));

        Assert.Equal(90, _repository.ServerSettings.PasswordMaxAgeDays);
    }

    [Fact]
    public void A_database_before_groups_upgrades_and_its_users_keep_working()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        var options = Options(connection);
        using (var db = new SettingsDbContext(options))
        {
            // The schema before issue #61, with user rows as the previous version wrote them.
            db.GetService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>().Migrate("20261114115734_AddUserStorageAndVirtualFolders");
            db.Database.ExecuteSqlRaw(
                "INSERT INTO ServerSettings (ServerRsaKey, ServerBanner, ListenToPort, BindToAddress, BlacklistedIps, MaxLoginAttemptsBeforeBan, " +
                "IdleTimeout, EnableCommand, EnableDirectTcpIp, OnlyWhitelistedIps, LoginFailureWindowSeconds, BanDurationSeconds, ExemptLoopbackFromBan) " +
                "VALUES ('old-key', NULL, 22, NULL, NULL, 0, 600, 0, 0, 0, 600, 1800, 1)");
            db.Database.ExecuteSqlRaw(
                "INSERT INTO Users (Username, UserRootDirectory, HashedPassword, OnlyWhitelistedIps, WhitelistedIps, LastSuccessfulLogin, Permissions, AllowedAuthMethods) " +
                "VALUES ('old', '/srv/old', 'hash', 0, '[]', '2026-01-02 03:04:05', '{{\"/\":\"All\"}}', 'All')");
            db.Database.ExecuteSqlRaw(
                "INSERT INTO Users (Username, UserRootDirectory, HashedPassword, OnlyWhitelistedIps, WhitelistedIps, LastSuccessfulLogin, Permissions, AllowedAuthMethods) " +
                "VALUES ('never', '/srv/never', NULL, 0, '[]', '0001-01-01 00:00:00', '{{\"/\":\"List\"}}', 'PublicKey')");
        }
        var before = DateTime.UtcNow.AddSeconds(-5);

        using var repository = new SqlSettingsRepository(options, createHostKey: () => throw new InvalidOperationException("must not be called"));

        var old = repository.GetUser("old");
        Assert.Equal(UserStatus.Enabled, old.Status);
        Assert.Null(old.ExpiresAt);
        Assert.Equal(0, old.MaxSessions);
        Assert.Null(old.PrimaryGroupId);
        Assert.Empty(old.SecondaryGroupIds);
        Assert.Equal(new DateTime(2026, 1, 2, 3, 4, 5), old.LastLoginAt);
        Assert.Null(old.Permissions); // "/" = All is the same as not set: a group can give permissions now
        Assert.True(old.PasswordChangedAt >= before, "The age of an existing password counts from the upgrade.");
        Assert.Null(UserLoginRulesRefusal(old));

        var never = repository.GetUser("never");
        Assert.Null(never.LastLoginAt);
        Assert.Equal(new Dictionary<string, FilePermissions> { ["/"] = FilePermissions.List }, never.Permissions);
        Assert.Null(never.PasswordChangedAt);
        Assert.Equal(0, repository.ServerSettings.PasswordMaxAgeDays);
        Assert.Empty(repository.GetGroups());
    }

    private static string? UserLoginRulesRefusal(User user) =>
        SshServer.Interfaces.Users.UserLoginRules.Refusal(user, AuthMethods.Password, DateTime.UtcNow, 0);

    [Fact]
    public void The_LiteDB_store_keeps_groups_and_the_lifecycle_fields_too()
    {
        using var temp = new TempDirectory();
        using var repository = new SettingsRepository(Path.Combine(temp.Path, "config.db"));
        var group = SampleGroup("sales", 7);
        Assert.True(repository.AddGroup(group));
        Assert.False(repository.AddGroup(new Group { Name = "Sales" }));
        repository.AddUser(new User { Username = "alice", Status = UserStatus.Disabled, MaxSessions = 2, PrimaryGroupId = group.Id });

        var stored = repository.GetGroup(group.Id)!;
        Assert.Equal(group.Permissions, stored.Permissions);
        Assert.Equal(AuthMethods.PublicKey, stored.AllowedAuthMethods);
        var alice = repository.GetUser("alice");
        Assert.Equal((UserStatus.Disabled, 2, group.Id), (alice.Status, alice.MaxSessions, alice.PrimaryGroupId!.Value));
        Assert.False(repository.RemoveGroup(group.Id)); // alice is a member

        stored.Name = "renamed";
        Assert.True(repository.UpdateGroup(stored));
        Assert.Equal(["renamed"], repository.GetGroups().Select(g => g.Name));
        alice.PrimaryGroupId = null;
        repository.UpdateUser(alice);
        Assert.True(repository.RemoveGroup(group.Id));
        Assert.Empty(repository.GetGroups());
    }
}
