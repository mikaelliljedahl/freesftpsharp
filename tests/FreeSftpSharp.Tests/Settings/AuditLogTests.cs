using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces;
using SshServer.Interfaces.Audit;
using SshServer.Interfaces.Events;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.Audit;

namespace FreeSftpSharp.Tests.Settings;

/// <summary>
/// The audit log in the SQLite settings database: the sink, the filters of the query, the retention job (with a fake
/// clock) and the provider events of the settings repository.
/// </summary>
public sealed class AuditLogTests : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly DateTimeOffset Now = new(2026, 11, 14, 3, 0, 0, TimeSpan.Zero);

    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<SettingsDbContext> _options;
    private readonly RecordingEventBus _bus = new();
    private readonly FakeTimeProvider _time = new(Now);
    private readonly SqlSettingsRepository _repository;
    private readonly SqlAuditLog _log;

    public AuditLogTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _options = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(_connection).Options;
        // The repository creates and migrates the database, as at the start of the server.
        _repository = new SqlSettingsRepository(_options, createHostKey: () => TestCredentials.HostKey, events: _bus, time: _time);
        _log = new SqlAuditLog(_options);
    }

    public void Dispose() => _connection.Dispose();

    private static FileEvent Upload(string user, DateTimeOffset at, FileEventStatus status = FileEventStatus.Ok) => new(FileEventType.Upload)
    {
        Timestamp = at, Username = user, VirtualPath = "/a.txt", FileSize = 42, Elapsed = TimeSpan.FromMilliseconds(250),
        Status = status, Protocol = "SFTP", RemoteIp = "192.0.2.1", Provider = "local",
    };

    [Fact]
    public async Task The_sink_writes_a_file_event_with_its_values()
    {
        var sink = new AuditSink(_log);

        await sink.HandleAsync(Upload("alice", Now), Ct);

        var entry = Assert.Single((await _log.QueryAsync(new AuditQuery(), Ct)).Entries);
        Assert.Equal(("File", "Upload", "Ok", "alice", "/a.txt", 42L, 250L, "192.0.2.1", "SFTP"),
            (entry.Category, entry.Type, entry.Status, entry.Username, entry.Path, entry.Size, entry.ElapsedMilliseconds, entry.RemoteIp, entry.Protocol));
        Assert.Equal(Now.UtcDateTime, entry.TimestampUtc);
        Assert.Contains("\"Provider\":\"local\"", entry.Details);
    }

    [Fact]
    public async Task The_sink_skips_FirstUpload_because_the_Upload_is_in_the_log()
    {
        var sink = new AuditSink(_log);

        await sink.HandleAsync(Upload("alice", Now) with { Type = FileEventType.FirstUpload }, Ct);

        Assert.Equal(0, (await _log.QueryAsync(new AuditQuery(), Ct)).TotalCount);
    }

    [Fact]
    public async Task The_query_filters_by_user_type_status_and_time_newest_first()
    {
        var sink = new AuditSink(_log);
        await sink.HandleAsync(Upload("alice", Now.AddHours(-3)), Ct);
        await sink.HandleAsync(Upload("Alice", Now.AddHours(-2), FileEventStatus.Error), Ct);
        await sink.HandleAsync(Upload("bob", Now.AddHours(-1)), Ct);
        await sink.HandleAsync(new AuthEvent(AuthEventType.LoginFailed) { Timestamp = Now, Username = "alice", Protocol = "SSH", Reason = "wrong password" }, Ct);

        var alice = await _log.QueryAsync(new AuditQuery { Username = "ALICE" }, Ct);
        Assert.Equal(3, alice.TotalCount);
        Assert.Equal(["LoginFailed", "Upload", "Upload"], alice.Entries.Select(e => e.Type));
        Assert.Equal(2, (await _log.QueryAsync(new AuditQuery { Username = "alice", Type = "Upload" }, Ct)).TotalCount);
        Assert.Equal("Failed", Assert.Single((await _log.QueryAsync(new AuditQuery { Status = "Failed" }, Ct)).Entries).Status);
        var window = await _log.QueryAsync(new AuditQuery { FromUtc = Now.AddHours(-2).UtcDateTime, ToUtc = Now.UtcDateTime }, Ct);
        Assert.Equal(["bob", "Alice"], window.Entries.Select(e => e.Username));
        var page = await _log.QueryAsync(new AuditQuery { Skip = 1, Take = 2 }, Ct);
        Assert.Equal((4, 2, "bob"), (page.TotalCount, page.Entries.Count, page.Entries[0].Username));
    }

    [Fact]
    public async Task The_retention_job_removes_entries_older_than_the_retention_and_publishes_a_system_event()
    {
        var sink = new AuditSink(_log);
        await sink.HandleAsync(Upload("old", Now.AddDays(-91)), Ct);
        await sink.HandleAsync(Upload("recent", Now.AddDays(-89)), Ct);
        var job = new AuditRetentionService(_log, Options.Create(new AuditOptions()), _time, NullLogger<AuditRetentionService>.Instance, _bus);

        var removed = await job.RunOnceAsync(Ct);

        Assert.Equal(1, removed);
        Assert.Equal(["recent"], (await _log.QueryAsync(new AuditQuery(), Ct)).Entries.Select(e => e.Username));
        Assert.Contains(_bus.Published, e => e is SystemEvent { Type: SystemEventType.ScheduledJobRan, Source: AuditRetentionService.JobName });
    }

    [Fact]
    public async Task The_retention_job_runs_at_the_start_and_again_each_day()
    {
        var sink = new AuditSink(_log);
        await sink.HandleAsync(Upload("old", Now.AddDays(-100)), Ct);
        await sink.HandleAsync(Upload("ages-tomorrow", Now.AddDays(-90).AddHours(12)), Ct);
        var job = new AuditRetentionService(_log, Options.Create(new AuditOptions { RetentionDays = 90 }), _time, NullLogger<AuditRetentionService>.Instance, _bus);

        // The job and the test share one in-memory SQLite connection, which does not allow two users at the same time.
        // The test therefore never polls the log while the job works: it waits for the signal of the end of a run, and
        // reads the log only between the runs, when the job waits for its timer. No wait depends on real time.
        var runs = new SemaphoreSlim(0);
        job.RunEnded = () => runs.Release();

        await job.StartAsync(Ct);
        try
        {
            await runs.WaitAsync(TimeSpan.FromMinutes(2), Ct); // a hang guard only, not a time condition
            Assert.Equal(["ages-tomorrow"], (await _log.QueryAsync(new AuditQuery(), Ct)).Entries.Select(e => e.Username));

            _time.Advance(AuditRetentionService.Interval);

            await runs.WaitAsync(TimeSpan.FromMinutes(2), Ct); // a hang guard only, not a time condition
            Assert.Equal(0, (await _log.QueryAsync(new AuditQuery(), Ct)).TotalCount);
        }
        finally
        {
            await job.StopAsync(Ct);
        }
    }

    [Fact]
    public async Task The_next_run_comes_one_interval_after_the_start_of_a_run_that_is_still_busy()
    {
        // The time moves on while the first run still works. The timer for the next run must exist already,
        // otherwise the job misses the interval and never runs again (a race in the first version).
        var log = new BlockingAuditLog();
        var job = new AuditRetentionService(log, Options.Create(new AuditOptions { RetentionDays = 90 }), _time, NullLogger<AuditRetentionService>.Instance);

        await job.StartAsync(Ct);
        try
        {
            await log.FirstRunStarted.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);
            _time.Advance(AuditRetentionService.Interval);
            log.ReleaseFirstRun.SetResult();

            await log.SecondRunStarted.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        }
        finally
        {
            log.ReleaseFirstRun.TrySetResult();
            await job.StopAsync(Ct);
        }
    }

    /// <summary>An audit log whose first delete waits until the test releases it.</summary>
    private sealed class BlockingAuditLog : IAuditLog
    {
        private int _runs;
        public TaskCompletionSource FirstRunStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseFirstRun { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource SecondRunStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool IsEnabled => true;

        public Task AppendAsync(AuditEntry entry, CancellationToken ct) => Task.CompletedTask;

        public Task<AuditQueryResult> QueryAsync(AuditQuery query, CancellationToken ct) => Task.FromResult(new AuditQueryResult([], 0));

        public async Task<int> DeleteOlderThanAsync(DateTime cutoffUtc, CancellationToken ct)
        {
            if (Interlocked.Increment(ref _runs) == 1)
            {
                FirstRunStarted.SetResult();
                await ReleaseFirstRun.Task.WaitAsync(ct);
            }
            else
            {
                SecondRunStarted.TrySetResult();
            }
            return 0;
        }
    }

    [Fact]
    public async Task A_retention_of_0_days_keeps_all_entries()
    {
        await new AuditSink(_log).HandleAsync(Upload("old", Now.AddYears(-5)), Ct);
        var job = new AuditRetentionService(_log, Options.Create(new AuditOptions { RetentionDays = 0 }), _time, NullLogger<AuditRetentionService>.Instance);

        Assert.Equal(0, await job.RunOnceAsync(Ct));
        Assert.Equal(1, (await _log.QueryAsync(new AuditQuery(), Ct)).TotalCount);
    }

    [Fact]
    public void A_negative_retention_is_not_valid()
    {
        Assert.True(new AuditOptionsValidator().Validate(null, new AuditOptions { RetentionDays = -1 }).Failed);
        Assert.True(new AuditOptionsValidator().Validate(null, new AuditOptions()).Succeeded);
    }

    [Fact]
    public void The_repository_publishes_user_changes_without_secrets()
    {
        var user = new User { Username = "carol", UserRootDirectory = "/srv/carol", HashedPassword = TestCredentials.HashPassword("secret-pw"), WhitelistedIps = [] };
        _repository.AddUser(user);
        user.UserRootDirectory = "/srv/carol2";
        user.HashedPassword = TestCredentials.HashPassword("another-pw");
        _repository.UpdateUser(user);
        _repository.RemoveUser("carol");

        var events = _bus.Published.OfType<ProviderEvent>().Where(e => e.ObjectType == ProviderObjectType.User).ToList();
        Assert.Equal([ProviderAction.Add, ProviderAction.Update, ProviderAction.Delete], events.Select(e => e.Action));
        Assert.All(events, e => Assert.Equal("carol", e.ObjectName));
        Assert.Equal(["UserRootDirectory", "Password"], events[1].ChangedFields);
        Assert.Equal(Now, events[0].Timestamp);
        var details = AuditEntryMapper.From(events[0]).Details!;
        Assert.Contains("\"HasPassword\":true", details);
        Assert.DoesNotContain(user.HashedPassword!, details);
        Assert.DoesNotContain("HashedPassword", details);
    }

    [Fact]
    public void A_login_time_update_gives_no_event()
    {
        var user = new User { Username = "dave", UserRootDirectory = "/srv/dave", WhitelistedIps = [] };
        _repository.AddUser(user);

        user.LastLoginAt = Now.UtcDateTime;
        _repository.UpdateUser(user);

        Assert.DoesNotContain(_bus.Published, e => e is ProviderEvent { Action: ProviderAction.Update });
    }

    [Fact]
    public void A_settings_change_gives_an_event_without_the_host_key()
    {
        var settings = _repository.ServerSettings;
        settings.ServerBanner = "AuditBanner";
        settings.ServerRsaKey = "new-key-material";

        _repository.UpdateServerSettings(settings);

        var change = Assert.Single(_bus.Published.OfType<ProviderEvent>(), e => e.ObjectType == ProviderObjectType.ServerSettings);
        Assert.Equal(["ServerBanner", "HostKey"], change.ChangedFields);
        Assert.DoesNotContain("new-key-material", AuditEntryMapper.From(change).Details);
    }
}
