using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.Admins;

namespace FreeSftpSharp.Tests.Settings;

/// <summary>The administrators and scope roles in the SQLite settings database (#60), and the upgrade of an older database.</summary>
public sealed class SqlAdminStoreTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<SettingsDbContext> _options;
    private readonly SqlSettingsRepository _repository;
    private readonly SqlAdminStore _store;

    public SqlAdminStoreTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _options = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(_connection).Options;
        _repository = new SqlSettingsRepository(_options, createHostKey: () => TestCredentials.HostKey);
        _store = new SqlAdminStore(_options);
    }

    public void Dispose()
    {
        _repository.Dispose();
        _connection.Dispose();
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task An_administrator_is_stored_with_all_fields_and_found_without_case()
    {
        Assert.False(await _store.AnyAdminAsync(Ct));
        var role = new Role { Name = "tenant-a", Description = "Tenant A" };
        Assert.True(await _store.AddRoleAsync(role, Ct));
        var admin = new Admin
        {
            Username = "Alice",
            PasswordHash = "PBKDF2-SHA256.100000.c2FsdA==.a2V5",
            Status = AdminStatus.Disabled,
            Email = "alice@example.org",
            Permissions = AdminPermissions.ManageUsers | AdminPermissions.ViewAudit,
            AllowedIps = ["10.0.0.0/8"],
            ScopeRoleId = role.Id,
            LastLoginAt = new DateTime(2026, 11, 1, 12, 0, 0, DateTimeKind.Utc),
            MustChangePassword = true,
        };

        Assert.True(await _store.AddAdminAsync(admin, Ct));
        Assert.False(await _store.AddAdminAsync(new Admin { Username = "ALICE", PasswordHash = "x" }, Ct));

        var stored = await _store.GetAdminAsync("alice", Ct);
        Assert.NotNull(stored);
        Assert.Equal(admin.Id, stored.Id);
        Assert.Equal(("Alice", AdminStatus.Disabled, "alice@example.org"), (stored.Username, stored.Status, stored.Email));
        Assert.Equal(AdminPermissions.ManageUsers | AdminPermissions.ViewAudit, stored.Permissions);
        Assert.Equal(["10.0.0.0/8"], stored.AllowedIps);
        Assert.Equal(role.Id, stored.ScopeRoleId);
        Assert.Equal(admin.LastLoginAt, stored.LastLoginAt);
        Assert.True(stored.MustChangePassword);
        Assert.True(await _store.AnyAdminAsync(Ct));
    }

    [Fact]
    public async Task The_permissions_are_stored_as_names()
    {
        await _store.AddAdminAsync(new Admin { Username = "bob", PasswordHash = "x", Permissions = AdminPermissions.ManageUsers | AdminPermissions.ManageSettings }, Ct);

        using var db = new SettingsDbContext(_options);
        var text = db.Database.SqlQueryRaw<string>("SELECT Permissions AS Value FROM Admins").Single();
        Assert.Equal("ManageUsers, ManageSettings", text);
    }

    [Fact]
    public async Task Update_and_remove_work_by_id()
    {
        var admin = new Admin { Username = "bob", PasswordHash = "x", Permissions = AdminPermissions.ManageUsers };
        await _store.AddAdminAsync(admin, Ct);

        admin.Permissions = AdminPermissions.SuperAdmin;
        admin.PasswordHash = "y";
        Assert.True(await _store.UpdateAdminAsync(admin, Ct));
        Assert.Equal((AdminPermissions.SuperAdmin, "y"), ((await _store.GetAdminAsync("bob", Ct))!.Permissions, (await _store.GetAdminAsync("bob", Ct))!.PasswordHash));

        Assert.True(await _store.RemoveAdminAsync(admin.Id, Ct));
        Assert.False(await _store.RemoveAdminAsync(admin.Id, Ct));
        Assert.False(await _store.UpdateAdminAsync(admin, Ct));
        Assert.Null(await _store.GetAdminAsync("bob", Ct));
    }

    [Fact]
    public async Task The_role_of_a_user_is_saved_and_a_used_role_cannot_be_removed()
    {
        var role = new Role { Name = "tenant-a" };
        await _store.AddRoleAsync(role, Ct);
        Assert.False(await _store.AddRoleAsync(new Role { Name = "TENANT-A" }, Ct));

        Assert.True(_repository.AddUser(new User { Username = "u1", UserRootDirectory = "/srv/u1", RoleId = role.Id }));
        Assert.Equal(role.Id, _repository.GetUser("u1").RoleId);

        // The foreign key protects the role as a last line (the service checks first, with a message).
        await Assert.ThrowsAsync<DbUpdateException>(async () =>
        {
            using var db = new SettingsDbContext(_options);
            db.Roles.Remove(db.Roles.Single());
            await db.SaveChangesAsync(Ct);
        });

        var user = _repository.GetUser("u1");
        user.RoleId = null;
        Assert.True(_repository.UpdateUser(user));
        Assert.Null(_repository.GetUser("u1").RoleId);
        Assert.True(await _store.RemoveRoleAsync(role.Id, Ct));
    }

    [Fact]
    public async Task An_older_database_is_upgraded_with_its_users_and_no_administrator()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        var options = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(connection).Options;
        using (var db = new SettingsDbContext(options))
        {
            // The schema before #60 (audit log, #65), with a user as that version wrote it.
            db.GetService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>().Migrate("20261114082326_AddAuditLog");
            db.Database.ExecuteSqlRaw(
                "INSERT INTO ServerSettings (ServerRsaKey, ServerBanner, ListenToPort, BindToAddress, BlacklistedIps, MaxLoginAttemptsBeforeBan, " +
                "IdleTimeout, EnableCommand, EnableDirectTcpIp, OnlyWhitelistedIps, LoginFailureWindowSeconds, BanDurationSeconds, ExemptLoopbackFromBan) " +
                "VALUES ('old-key', NULL, 22, NULL, NULL, 0, 600, 0, 0, 0, 600, 1800, 1)");
            db.Database.ExecuteSqlRaw(
                "INSERT INTO Users (Username, UserRootDirectory, HashedPassword, RsaPublicKey, OnlyWhitelistedIps, WhitelistedIps, LastSuccessfulLogin, Permissions) " +
                "VALUES ('Old', '/srv/old', 'hash', 'key', 1, '[\"10.0.0.0/8\"]', '2026-01-02 03:04:05', '{{\"/\":\"All\"}}')");
        }

        using var repository = new SqlSettingsRepository(options, createHostKey: () => throw new InvalidOperationException("must not be called"));
        var store = new SqlAdminStore(options);

        var user = repository.GetUser("old");
        Assert.Equal(("Old", "/srv/old", "hash"), (user.Username, user.UserRootDirectory, user.HashedPassword));
        Assert.Null(user.RoleId);
        // The table rebuild for the foreign key keeps the case-insensitive user names.
        Assert.False(repository.AddUser(new User { Username = "OLD", UserRootDirectory = "/srv/x" }));
        Assert.False(await store.AnyAdminAsync(Ct));
        using (var db = new SettingsDbContext(options))
            Assert.Equal("20261114112133_AddAdminsAndRoles", db.Database.GetAppliedMigrations().Last());
    }
}
