using System.Text.Json;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using Microsoft.Extensions.Time.Testing;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;
using SshServerModule.Quotas;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Quotas;

/// <summary>The counters (<see cref="QuotaUsageTracker"/>), the scan, the provider events and the factory with quotas.</summary>
public sealed class QuotaServicesTests : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly QuotaScope Alice = QuotaScope.ForUser("alice");

    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 11, 14, 10, 0, 0, TimeSpan.Zero));
    private readonly FlakyStore _store = new();
    private readonly TempDirectory _root = new();
    private readonly QuotaUsageTracker _tracker;

    public QuotaServicesTests()
    {
        _tracker = new QuotaUsageTracker(_store, _clock);
    }

    public void Dispose() => _root.Dispose();

    [Fact]
    public async Task A_reservation_is_refused_when_it_would_go_over_the_limit_and_then_changes_nothing()
    {
        await _tracker.LoadAsync(Alice, Ct);
        var limit = new DiskQuota { MaxSizeBytes = 100, MaxFiles = 1 };

        Assert.True(_tracker.TryReserveDisk(Alice, limit, 60, 1));
        Assert.False(_tracker.TryReserveDisk(Alice, limit, 41, 0));
        Assert.False(_tracker.TryReserveDisk(Alice, limit, 0, 1));
        Assert.True(_tracker.TryReserveDisk(Alice, limit, 40, 0));

        Assert.Equal((100L, 1L), (_tracker.Current(Alice).UsedBytes, _tracker.Current(Alice).UsedFiles));
    }

    [Fact]
    public async Task A_flush_writes_the_changes_as_increments_and_a_failed_flush_keeps_them()
    {
        await _tracker.LoadAsync(Alice, Ct);
        _tracker.AddDisk(Alice, 500, 2);
        _store.Fail = true;

        await _tracker.FlushAsync(Ct);
        Assert.Null(await _store.Inner.GetAsync(Alice, Ct));
        Assert.Equal(500, _tracker.Current(Alice).UsedBytes);

        _store.Fail = false;
        _tracker.AddDisk(Alice, 100, 0);
        await _tracker.FlushAsync(Ct);

        Assert.Equal((600L, 2L), ((await _store.Inner.GetAsync(Alice, Ct))!.UsedBytes, (await _store.Inner.GetAsync(Alice, Ct))!.UsedFiles));
        Assert.Equal(600, _tracker.Current(Alice).UsedBytes);
        Assert.Equal(1, _store.Adds); // nothing to write: no second store call
        await _tracker.FlushAsync(Ct);
        Assert.Equal(1, _store.Adds);
    }

    [Fact]
    public async Task An_unchanged_scope_is_read_again_after_a_while_so_the_changes_of_other_nodes_come_in()
    {
        await _tracker.LoadAsync(Alice, Ct);
        await _store.Inner.AddAsync(Alice, new QuotaUsageDelta(700, 1, 0, 0), _clock.GetUtcNow(), Ct); // another node

        Assert.Equal(0, (await _tracker.LoadAsync(Alice, Ct)).UsedBytes);
        _clock.Advance(QuotaUsageTracker.RefreshAfter + TimeSpan.FromSeconds(1));
        Assert.Equal(700, (await _tracker.LoadAsync(Alice, Ct)).UsedBytes);
    }

    [Fact]
    public async Task A_scan_counts_the_files_without_the_mount_paths_and_sets_the_counters()
    {
        Directory.CreateDirectory(_root.File("a/b"));
        Directory.CreateDirectory(_root.File("shared"));
        File.WriteAllBytes(_root.File("one.bin"), new byte[100]);
        File.WriteAllBytes(_root.File("a/b/two.bin"), new byte[250]);
        File.WriteAllBytes(_root.File("shared/hidden-by-the-mount.bin"), new byte[9_999]);
        using var other = new TempDirectory();
        var folderRoot = other.Path;
        File.WriteAllBytes(Path.Combine(folderRoot, "f.bin"), new byte[42]);

        var repository = new InMemorySettingsRepository(new ServerSettings());
        var folder = new VirtualFolder { Name = "shared", Storage = Local(folderRoot) };
        repository.AddVirtualFolder(folder);
        repository.AddUser(new User
        {
            Username = "alice",
            UserRootDirectory = _root.Path,
            DiskQuota = new DiskQuota { MaxSizeBytes = 1_000_000 },
            VirtualFolders = [new VirtualFolderMount { VirtualFolderId = folder.Id, MountPath = "/shared", Quota = new DiskQuota { MaxFiles = 5 } }],
        });
        await _tracker.LoadAsync(Alice, Ct);
        _tracker.AddDisk(Alice, 1, 1); // a change that the scan replaces
        var scanner = Scanner(repository, new QuotaScanQueue());

        var usage = await scanner.ScanAsync(Alice, Ct);
        var folderUsage = await scanner.ScanAsync(QuotaScope.ForFolder(folder.Id), Ct);

        Assert.Equal((350L, 2L), (usage!.UsedBytes, usage.UsedFiles));
        Assert.Equal(_clock.GetUtcNow(), usage.ScannedAt);
        Assert.Equal((350L, 2L), (_tracker.Current(Alice).UsedBytes, _tracker.Current(Alice).UsedFiles));
        Assert.Equal((42L, 1L), (folderUsage!.UsedBytes, folderUsage.UsedFiles));
        Assert.Null(await scanner.ScanAsync(QuotaScope.ForUser("nobody"), Ct));
        Assert.Equal([Alice, QuotaScope.ForFolder(folder.Id)], scanner.ScopesWithQuota(repository.GetUser("alice")));
    }

    [Fact]
    public async Task A_queued_user_request_scans_every_scope_of_the_user_with_a_quota()
    {
        File.WriteAllBytes(_root.File("x.bin"), new byte[10]);
        var repository = new InMemorySettingsRepository(new ServerSettings());
        repository.AddUser(new User { Username = "alice", UserRootDirectory = _root.Path, DiskQuota = new DiskQuota { MaxFiles = 3 } });
        var queue = new QuotaScanQueue();
        var scanner = Scanner(repository, queue);

        Assert.True(queue.RequestUser("alice"));
        Assert.False(queue.RequestUser("alice")); // already queued
        Assert.True(queue.IsUserPending("alice"));
        await scanner.RunPendingAsync(Ct);

        Assert.False(queue.IsUserPending("alice"));
        Assert.Equal(1, _tracker.Current(Alice).UsedFiles);
        Assert.Equal(1, scanner.RequestAllWithQuota());
    }

    [Fact]
    public async Task The_provider_events_remove_the_counters_of_a_removed_user_and_queue_a_scan_when_a_quota_changes()
    {
        var queue = new QuotaScanQueue();
        var sink = new QuotaProviderEventSink(_tracker, queue);
        await _store.Inner.AddAsync(Alice, new QuotaUsageDelta(5, 1, 0, 0), _clock.GetUtcNow(), Ct);

        await sink.HandleAsync(new ProviderEvent(ProviderAction.Update, ProviderObjectType.User, "alice") { ChangedFields = ["OnlyWhitelistedIps"] }, Ct);
        Assert.False(queue.IsUserPending("alice"));
        await sink.HandleAsync(new ProviderEvent(ProviderAction.Update, ProviderObjectType.User, "alice") { ChangedFields = [nameof(UserSnapshot.DiskQuota)] }, Ct);
        Assert.True(queue.IsUserPending("alice"));

        await sink.HandleAsync(new ProviderEvent(ProviderAction.Delete, ProviderObjectType.User, "alice"), Ct);
        Assert.Null(await _store.Inner.GetAsync(Alice, Ct));

        await _store.Inner.AddAsync(QuotaScope.ForFolder(7), new QuotaUsageDelta(5, 1, 0, 0), _clock.GetUtcNow(), Ct);
        await sink.HandleAsync(new ProviderEvent(ProviderAction.Delete, ProviderObjectType.VirtualFolder, "f") { Object = new VirtualFolderSnapshot(7, "f", null, "local") }, Ct);
        Assert.Null(await _store.Inner.GetAsync(QuotaScope.ForFolder(7), Ct));
    }

    [Fact]
    public async Task A_user_without_a_quota_gets_no_decorator_and_a_user_with_one_queues_the_first_scan()
    {
        var queue = new QuotaScanQueue();
        var decorators = new QuotaDecorators(new EffectiveQuotaService(), _tracker, queue, _clock);
        var factory = TestStorage.Factory([new LocalDiskStorageProvider()], _ => new UserStorageResolver(new UserRootDefaultStorage()), quotas: decorators);
        var client = new ClientContext("SFTP", "127.0.0.1");

        var plain = await factory.CreateAsync(new User { Username = "plain", UserRootDirectory = _root.Path }, client, Ct);
        Assert.IsType<LocalFileSystem>(plain);
        Assert.Empty(_tracker.DiskScopes());

        var limited = await factory.CreateAsync(new User
        {
            Username = "alice",
            UserRootDirectory = _root.Path,
            DiskQuota = new DiskQuota { MaxSizeBytes = 10 },
            TransferQuota = new TransferQuota { MaxUploadBytes = 10 },
            Bandwidth = new BandwidthLimit { DownloadKiBPerSecond = 1 },
        }, client, Ct);
        Assert.IsType<BandwidthFileSystem>(limited);
        Assert.True(queue.IsPending(Alice));
        Assert.Equal([Alice], _tracker.DiskScopes().Select(s => s.Key));
    }

    [Fact]
    public async Task The_event_rule_actions_queue_a_scan_and_reset_the_transfer_counters()
    {
        var queue = new QuotaScanQueue();
        var user = new User { Username = "alice" };
        var context = new SshServer.Interfaces.EventRules.EventActionContext(new SshServer.Interfaces.EventRules.EventRule(), null, user,
            new Dictionary<string, string>(), new Dictionary<string, string>(), _clock.GetUtcNow(), t => t);
        await _tracker.LoadAsync(Alice, Ct);
        _tracker.AddTransfer(Alice, 10, 20);

        var scan = await new QuotaScanRuleAction(queue).ExecuteAsync(context, Ct);
        var reset = await new QuotaResetTransferRuleAction(_tracker).ExecuteAsync(context, Ct);

        Assert.False(scan.IsFailure);
        Assert.True(queue.IsUserPending("alice"));
        Assert.False(reset.IsFailure);
        Assert.Equal((0L, 0L), (_tracker.Current(Alice).UploadedBytes, _tracker.Current(Alice).DownloadedBytes));
    }

    private QuotaScanService Scanner(ISettingsRepository repository, QuotaScanQueue queue)
    {
        var providers = new SshServerModule.Storage.StorageProviderRegistry([new LocalDiskStorageProvider()]);
        var codec = TestStorage.Codec(new LocalDiskStorageProvider());
        return new QuotaScanService(new UserStorageResolver(new UserRootDefaultStorage(), repository), providers, codec,
            new EffectiveQuotaService(), _tracker, queue, repository, time: _clock);
    }

    private static StorageConfig Local(string root)
        => new() { Provider = LocalDiskStorageProvider.ProviderName, Options = JsonSerializer.Serialize(new LocalDiskStorageOptions(root)) };

    /// <summary>The in-memory store, with writes that fail on request.</summary>
    private sealed class FlakyStore : IQuotaUsageStore
    {
        public InMemoryQuotaUsageStore Inner { get; } = new();
        public bool Fail { get; set; }
        public int Adds { get; private set; }

        public Task<QuotaUsage?> GetAsync(QuotaScope scope, CancellationToken ct) => Inner.GetAsync(scope, ct);

        public Task<QuotaUsage> AddAsync(QuotaScope scope, QuotaUsageDelta delta, DateTimeOffset now, CancellationToken ct)
        {
            if (Fail)
                throw new IOException("The database is not reachable.");
            Adds++;
            return Inner.AddAsync(scope, delta, now, ct);
        }

        public Task<QuotaUsage> SetDiskUsageAsync(QuotaScope scope, long usedBytes, long usedFiles, DateTimeOffset scannedAt, CancellationToken ct)
            => Inner.SetDiskUsageAsync(scope, usedBytes, usedFiles, scannedAt, ct);

        public Task<QuotaUsage> ResetTransferAsync(QuotaScope scope, DateTimeOffset now, CancellationToken ct) => Inner.ResetTransferAsync(scope, now, ct);

        public Task RemoveAsync(QuotaScope scope, CancellationToken ct) => Inner.RemoveAsync(scope, ct);
    }
}
