using FreeSftpSharp.Tests.Settings.Providers;
using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using SshServer.Interfaces;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.Quotas;
using SshServerModule.Quotas;

namespace FreeSftpSharp.Tests.Settings;

/// <summary>The quotas (issue #62) in the settings database: the migration, the quota fields of users and mounts, and the counters.</summary>
public sealed class QuotaSettingsTests : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly DateTimeOffset Now = new(2026, 11, 14, 10, 0, 0, TimeSpan.Zero);

    private readonly TestDatabase _database;
    private readonly DbContextOptions<SettingsDbContext> _options;
    private readonly RecordingEventBus _events = new();
    private readonly SqlSettingsRepository _repository;

    public QuotaSettingsTests()
    {
        _database = TestDatabase.CreateDefault();
        _options = _database.Options;
        _repository = new SqlSettingsRepository(_options, createHostKey: () => TestCredentials.HostKey, events: _events);
    }

    public void Dispose()
    {
        _repository.Dispose();
        _database.Dispose();
    }

    private VirtualFolder AddFolder(string name)
    {
        var folder = new VirtualFolder { Name = name, Storage = new StorageConfig { Provider = "local", Options = "{\"RootDirectory\":\"/srv/x\"}" } };
        Assert.True(_repository.AddVirtualFolder(folder));
        return folder;
    }

    [Fact]
    public void An_existing_database_upgrades_and_its_users_have_no_quota()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        var options = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(connection).Options;
        using (var db = new SettingsDbContext(options))
        {
            // The schema before issue #62, with a user row and a mount as the previous version wrote them.
            db.GetService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>().Migrate("20261114115734_AddUserStorageAndVirtualFolders");
            db.Database.ExecuteSqlRaw(
                "INSERT INTO ServerSettings (ServerRsaKey, ServerBanner, ListenToPort, BindToAddress, BlacklistedIps, MaxLoginAttemptsBeforeBan, " +
                "IdleTimeout, EnableCommand, EnableDirectTcpIp, OnlyWhitelistedIps, LoginFailureWindowSeconds, BanDurationSeconds, ExemptLoopbackFromBan) " +
                "VALUES ('old-key', NULL, 22, NULL, NULL, 0, 600, 0, 0, 0, 600, 1800, 1)");
            db.Database.ExecuteSqlRaw("INSERT INTO VirtualFolders (Name, Description, Storage) VALUES ('shared', NULL, '{{\"Provider\":\"local\",\"Options\":\"{{}}\"}}')");
            db.Database.ExecuteSqlRaw(
                "INSERT INTO Users (Username, UserRootDirectory, HashedPassword, OnlyWhitelistedIps, WhitelistedIps, LastSuccessfulLogin, Permissions, AllowedAuthMethods) " +
                "VALUES ('old', '/srv/old', 'hash', 0, '[]', '2026-01-02 03:04:05', '{{\"/\":\"All\"}}', 'All')");
            db.Database.ExecuteSqlRaw("INSERT INTO UserVirtualFolders (UserId, VirtualFolderId, MountPath) SELECT Id, 1, '/shared' FROM Users");
        }

        using var repository = new SqlSettingsRepository(options, createHostKey: () => throw new InvalidOperationException("must not be called"));

        var user = repository.GetUser("old");
        Assert.Null(user.DiskQuota);
        Assert.Null(user.TransferQuota);
        Assert.Null(user.Bandwidth);
        Assert.Null(Assert.Single(user.VirtualFolders).Quota);
        Assert.True(new EffectiveQuotaService(new SshServer.Interfaces.Users.EffectiveUserSettingsService(repository)).Resolve(user).IsUnlimited);
        using (var db = new SettingsDbContext(options))
        {
            Assert.Contains(db.Database.GetAppliedMigrations(), m => m.EndsWith("_AddQuotas", StringComparison.Ordinal));
            Assert.Empty(db.QuotaUsages);
        }
    }

    [Fact]
    public void The_quotas_of_a_user_and_of_its_mounts_are_saved_and_changed()
    {
        var shared = AddFolder("shared");
        var user = new User
        {
            Username = "alice",
            UserRootDirectory = "/srv/alice",
            DiskQuota = new DiskQuota { MaxSizeBytes = 1_048_576, MaxFiles = 10 },
            TransferQuota = new TransferQuota { MaxUploadBytes = 5, MaxTotalBytes = 9 },
            Bandwidth = new BandwidthLimit
            {
                UploadKiBPerSecond = 256,
                DownloadKiBPerSecond = 512,
                Overrides = [new BandwidthOverride { Sources = ["10.0.0.0/8"], UploadKiBPerSecond = 0, DownloadKiBPerSecond = 0 }],
            },
            VirtualFolders = [new VirtualFolderMount { VirtualFolderId = shared.Id, MountPath = "/shared", Quota = new DiskQuota { MaxSizeBytes = 2048 } }],
        };
        Assert.True(_repository.AddUser(user));

        var stored = _repository.GetUser("alice");
        Assert.Equal((1_048_576L, 10L), (stored.DiskQuota!.MaxSizeBytes, stored.DiskQuota.MaxFiles));
        Assert.Equal((5L, 0L, 9L), (stored.TransferQuota!.MaxUploadBytes, stored.TransferQuota.MaxDownloadBytes, stored.TransferQuota.MaxTotalBytes));
        Assert.Equal((256, 512), (stored.Bandwidth!.UploadKiBPerSecond, stored.Bandwidth.DownloadKiBPerSecond));
        Assert.Equal(["10.0.0.0/8"], Assert.Single(stored.Bandwidth.Overrides!).Sources);
        Assert.Equal(2048, Assert.Single(stored.VirtualFolders).Quota!.MaxSizeBytes);

        // A change of the quota of the same mount, and of the user quota: both are saved and the event names them.
        stored.VirtualFolders[0].Quota = new DiskQuota { MaxSizeBytes = 4096 };
        stored.DiskQuota = new DiskQuota { MaxSizeBytes = 2_097_152 };
        Assert.True(_repository.UpdateUser(stored));

        var changed = _repository.GetUser("alice");
        Assert.Equal(4096, Assert.Single(changed.VirtualFolders).Quota!.MaxSizeBytes);
        Assert.Equal(2_097_152, changed.DiskQuota!.MaxSizeBytes);
        var update = _events.Published.OfType<ProviderEvent>().Last(e => e.Action == ProviderAction.Update);
        Assert.Contains(nameof(UserSnapshot.DiskQuota), update.ChangedFields);
        Assert.Contains("/shared: 4096 bytes", ((UserSnapshot)update.Object!).DiskQuota);
    }

    [Fact]
    public async Task The_counters_are_inserted_then_incremented_and_set_by_a_scan()
    {
        var store = new SqlQuotaUsageStore(_options);
        var scope = QuotaScope.ForUser("alice");

        Assert.Null(await store.GetAsync(scope, Ct));
        var first = await store.AddAsync(scope, new QuotaUsageDelta(100, 1, 100, 0), Now, Ct);
        Assert.Equal((100L, 1L, 100L, 0L), (first.UsedBytes, first.UsedFiles, first.UploadedBytes, first.DownloadedBytes));
        Assert.Null(first.ScannedAt);

        var second = await store.AddAsync(scope, new QuotaUsageDelta(-40, 0, 0, 7), Now.AddSeconds(5), Ct);
        Assert.Equal((60L, 1L, 100L, 7L), (second.UsedBytes, second.UsedFiles, second.UploadedBytes, second.DownloadedBytes));
        Assert.Equal(Now.AddSeconds(5), second.UpdatedAt);

        var scanned = await store.SetDiskUsageAsync(scope, 5_000, 3, Now.AddMinutes(1), Ct);
        Assert.Equal((5_000L, 3L, 100L, 7L), (scanned.UsedBytes, scanned.UsedFiles, scanned.UploadedBytes, scanned.DownloadedBytes));
        Assert.Equal(Now.AddMinutes(1), scanned.ScannedAt);

        var reset = await store.ResetTransferAsync(scope, Now.AddMinutes(2), Ct);
        Assert.Equal((5_000L, 3L, 0L, 0L), (reset.UsedBytes, reset.UsedFiles, reset.UploadedBytes, reset.DownloadedBytes));

        await store.RemoveAsync(scope, Ct);
        Assert.Null(await store.GetAsync(scope, Ct));
    }

    [Fact]
    public async Task Two_nodes_add_to_the_same_counter()
    {
        var scope = QuotaScope.ForFolder(3);
        var node1 = new QuotaUsageTracker(new SqlQuotaUsageStore(_options));
        var node2 = new QuotaUsageTracker(new SqlQuotaUsageStore(_options));
        await node1.LoadAsync(scope, Ct);
        await node2.LoadAsync(scope, Ct);

        node1.AddDisk(scope, 1_000, 1);
        node2.AddDisk(scope, 500, 1);
        await node1.FlushAsync(Ct);
        await node2.FlushAsync(Ct);

        Assert.Equal((1_500L, 2L), (node2.Current(scope).UsedBytes, node2.Current(scope).UsedFiles)); // the flush gives back the stored sum
        var stored = await new SqlQuotaUsageStore(_options).GetAsync(scope, Ct);
        Assert.Equal((1_500L, 2L), (stored!.UsedBytes, stored.UsedFiles));
    }
}
