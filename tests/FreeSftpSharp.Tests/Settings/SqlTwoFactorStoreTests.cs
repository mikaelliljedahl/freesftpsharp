using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.TwoFactor;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.Admins;
using SshServer.Settings.Sql.TwoFactor;

namespace FreeSftpSharp.Tests.Settings;

/// <summary>The TOTP enrolments in the SQLite settings database (#63): the version check, and the removal with the owner.</summary>
public sealed class SqlTwoFactorStoreTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<SettingsDbContext> _options;
    private readonly SqlSettingsRepository _repository;
    private readonly SqlTwoFactorStore _store;

    public SqlTwoFactorStoreTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _options = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(_connection).Options;
        _repository = new SqlSettingsRepository(_options, createHostKey: () => TestCredentials.HostKey);
        _store = new SqlTwoFactorStore(_options);
    }

    public void Dispose()
    {
        _repository.Dispose();
        _connection.Dispose();
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private TwoFactorSubject AddUser(string name)
    {
        var user = new User { Username = name, UserRootDirectory = "/tmp" };
        Assert.True(_repository.AddUser(user));
        return TwoFactorSubject.ForUser(_repository.GetUser(name));
    }

    private static TwoFactorEnrolment Enrolment(TwoFactorSubject subject, bool enabled = false) => new()
    {
        Subject = subject,
        ProtectedSecret = "protected",
        Enabled = enabled,
        LastUsedStep = 42,
        RecoveryCodeHashes = ["h1", "h2"],
        CreatedAt = new DateTime(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc),
        EnabledAt = enabled ? new DateTime(2026, 11, 14, 12, 1, 0, DateTimeKind.Utc) : null,
    };

    [Fact]
    public async Task An_enrolment_is_stored_with_all_fields()
    {
        var alice = AddUser("alice");

        var saved = await _store.ReplaceAsync(Enrolment(alice, enabled: true), Ct);
        var stored = await _store.GetAsync(alice, Ct);

        Assert.NotNull(stored);
        Assert.Equal(saved, stored with { RecoveryCodeHashes = saved.RecoveryCodeHashes });
        Assert.Equal(new[] { "h1", "h2" }, stored.RecoveryCodeHashes);
        Assert.Equal(42, stored.LastUsedStep);
        Assert.Equal(DateTimeKind.Utc, stored.CreatedAt.Kind);
        Assert.Null(await _store.GetAsync(new TwoFactorSubject(TwoFactorSubjectKind.Admin, alice.Id), Ct));
    }

    [Fact]
    public async Task An_update_with_an_old_version_is_refused()
    {
        var alice = AddUser("alice");
        var saved = await _store.ReplaceAsync(Enrolment(alice, enabled: true), Ct);

        Assert.True(await _store.TryUpdateAsync(saved with { LastUsedStep = 43 }, Ct));
        // A second login read the same version: its update must fail, so one code cannot log in twice.
        Assert.False(await _store.TryUpdateAsync(saved with { LastUsedStep = 43 }, Ct));

        var stored = (await _store.GetAsync(alice, Ct))!;
        Assert.Equal(43, stored.LastUsedStep);
        Assert.Equal(saved.Version + 1, stored.Version);
    }

    [Fact]
    public async Task Replace_and_remove_change_only_the_subject()
    {
        var alice = AddUser("alice");
        var bob = AddUser("bob");
        await _store.ReplaceAsync(Enrolment(alice, enabled: true), Ct);
        await _store.ReplaceAsync(Enrolment(bob), Ct);
        await _store.ReplaceAsync(Enrolment(bob) with { ProtectedSecret = "new" }, Ct);

        Assert.Equal("new", (await _store.GetAsync(bob, Ct))!.ProtectedSecret);
        Assert.Equal(new[] { alice.Id }, await _store.ListEnabledAsync(TwoFactorSubjectKind.User, Ct));

        Assert.True(await _store.RemoveAsync(bob, Ct));
        Assert.False(await _store.RemoveAsync(bob, Ct));
        Assert.NotNull(await _store.GetAsync(alice, Ct));
    }

    [Fact]
    public async Task The_enrolment_is_removed_with_its_user_and_a_new_user_of_the_same_name_has_none()
    {
        var alice = AddUser("alice");
        await _store.ReplaceAsync(Enrolment(alice, enabled: true), Ct);

        Assert.True(_repository.RemoveUser("alice"));
        var again = AddUser("alice");

        Assert.Null(await _store.GetAsync(alice, Ct));
        Assert.Null(await _store.GetAsync(again, Ct));
    }

    [Fact]
    public async Task The_enrolment_of_an_administrator_is_removed_with_it()
    {
        var admins = new SqlAdminStore(_options);
        var admin = new Admin { Username = "root", PasswordHash = "x", Permissions = AdminPermissions.SuperAdmin };
        Assert.True(await admins.AddAdminAsync(admin, Ct));
        var subject = TwoFactorSubject.ForAdmin(admin);
        await _store.ReplaceAsync(Enrolment(subject, enabled: true), Ct);
        Assert.Equal(new[] { admin.Id }, await _store.ListEnabledAsync(TwoFactorSubjectKind.Admin, Ct));

        Assert.True(await admins.RemoveAdminAsync(admin.Id, Ct));

        Assert.Null(await _store.GetAsync(subject, Ct));
    }

    [Fact]
    public async Task The_lite_db_provider_refuses_a_setup()
    {
        var store = new DisabledTwoFactorStore();

        Assert.Null(await store.GetAsync(new TwoFactorSubject(TwoFactorSubjectKind.User, 1), Ct));
        await Assert.ThrowsAsync<NotSupportedException>(() => store.ReplaceAsync(Enrolment(new TwoFactorSubject(TwoFactorSubjectKind.User, 1)), Ct));
    }
}
