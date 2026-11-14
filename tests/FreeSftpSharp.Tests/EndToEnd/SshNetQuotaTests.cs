using System.Diagnostics;
using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet;
using Renci.SshNet.Common;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;
using SshServerModule.Quotas;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// The server with the quota decorators of the hosts (issue #62), counters in memory. Each test adds its own user with
/// its own root directory and limits (<see cref="AddQuotaUser"/>), so the tests of the class do not share counters.
/// </summary>
public sealed class QuotaSftpServerFixture : SftpServerFixture
{
    public QuotaUsageTracker Tracker { get; } = new(new InMemoryQuotaUsageStore());
    public QuotaScanQueue Scans { get; } = new();

    protected override IFileSystemFactory CreateFileSystemFactory(IConnectionRegistry connections, IEventBus? events, ISettingsRepository repository)
        => TestStorage.Factory(StorageProviders(), _ => new UserStorageResolver(new UserRootDefaultStorage(), repository), connections, events,
            new QuotaDecorators(new EffectiveQuotaService(), Tracker, Scans));

    /// <summary>The scan of the hosts over the repository of the running server.</summary>
    public QuotaScanService Scanner => new(new UserStorageResolver(new UserRootDefaultStorage(), Repository),
        new StorageProviderRegistry([new LocalDiskStorageProvider()]), TestStorage.Codec(new LocalDiskStorageProvider()),
        new EffectiveQuotaService(), Tracker, Scans, Repository);

    /// <summary>Adds a user (password of the test user) with an empty root directory of its own; returns the root.</summary>
    public string AddQuotaUser(string username, Action<User> configure)
    {
        var root = Path.Combine(TempDirectory, "users", username);
        Directory.CreateDirectory(root);
        var user = new User
        {
            Username = username,
            HashedPassword = TestCredentials.HashPassword(Password),
            UserRootDirectory = root,
            WhitelistedIps = [],
        };
        configure(user);
        Assert.True(Repository.AddUser(user));
        return root;
    }

    public SftpClient Connect(string username)
    {
        var client = CreateClient(username: username);
        client.Connect();
        return client;
    }
}

/// <summary>SSH.NET against users with a disk quota, a transfer quota and a bandwidth limit (issue #62).</summary>
public sealed class SshNetQuotaTests : IClassFixture<QuotaSftpServerFixture>
{
    private const int KiB = 1024;
    private readonly QuotaSftpServerFixture _server;

    public SshNetQuotaTests(QuotaSftpServerFixture server)
    {
        _server = server;
    }

    private static void Upload(SftpClient client, string path, int size)
    {
        using var stream = new MemoryStream(new byte[size]);
        client.UploadFile(stream, path);
    }

    [Fact]
    public async Task An_upload_over_the_disk_quota_fails_with_quota_exceeded_and_leaves_no_partial_file()
    {
        var root = _server.AddQuotaUser("quota-disk", u => u.DiskQuota = new DiskQuota { MaxSizeBytes = 1024 * KiB });
        var scope = QuotaScope.ForUser("quota-disk");
        await _server.Scanner.ScanAsync(scope, TestContext.Current.CancellationToken); // the first scan, as the host runs it at the first session
        using var client = _server.Connect("quota-disk");

        Upload(client, "/first.bin", 900 * KiB);
        Assert.Equal(900 * KiB, _server.Tracker.Current(scope).UsedBytes);

        var ex = Assert.ThrowsAny<SshException>(() => Upload(client, "/second.bin", 200 * KiB));
        Assert.Contains("Quota exceeded", ex.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(root, "second.bin")), "The partial file must be removed.");
        Assert.Equal((900L * KiB, 1L), (_server.Tracker.Current(scope).UsedBytes, _server.Tracker.Current(scope).UsedFiles));

        client.DeleteFile("/first.bin");
        Upload(client, "/second.bin", 200 * KiB);

        Assert.Equal(200 * KiB, new FileInfo(Path.Combine(root, "second.bin")).Length);
        Assert.Equal((200L * KiB, 1L), (_server.Tracker.Current(scope).UsedBytes, _server.Tracker.Current(scope).UsedFiles));
        var space = client.GetStatus("/");
        Assert.Equal(1024UL * KiB, space.TotalBlocks * space.BlockSize);
    }

    [Fact]
    public async Task A_rescan_corrects_the_counters_after_files_were_added_outside_the_server()
    {
        var root = _server.AddQuotaUser("quota-scan", u => u.DiskQuota = new DiskQuota { MaxFiles = 3 });
        var scope = QuotaScope.ForUser("quota-scan");
        await _server.Scanner.ScanAsync(scope, TestContext.Current.CancellationToken);
        using var client = _server.Connect("quota-scan");
        Upload(client, "/a.bin", 10);
        Directory.CreateDirectory(Path.Combine(root, "outside"));
        File.WriteAllBytes(Path.Combine(root, "outside", "b.bin"), new byte[20]);
        File.WriteAllBytes(Path.Combine(root, "outside", "c.bin"), new byte[30]);
        Assert.Equal(1, _server.Tracker.Current(scope).UsedFiles);

        await _server.Scanner.ScanAsync(scope, TestContext.Current.CancellationToken);

        Assert.Equal((60L, 3L), (_server.Tracker.Current(scope).UsedBytes, _server.Tracker.Current(scope).UsedFiles));
        var ex = Assert.ThrowsAny<SshException>(() => Upload(client, "/d.bin", 1)); // the fourth file
        Assert.Contains("Quota exceeded", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_download_over_the_transfer_quota_fails()
    {
        var root = _server.AddQuotaUser("quota-transfer", u => u.TransferQuota = new TransferQuota { MaxDownloadBytes = 100 * KiB });
        File.WriteAllBytes(Path.Combine(root, "big.bin"), new byte[300 * KiB]);
        using var client = _server.Connect("quota-transfer");

        var ex = Assert.ThrowsAny<SshException>(() => client.DownloadFile("/big.bin", new MemoryStream()));

        Assert.Contains("Quota exceeded", ex.Message, StringComparison.Ordinal);
        Assert.Equal(100 * KiB, _server.Tracker.Current(QuotaScope.ForUser("quota-transfer")).DownloadedBytes);
    }

    /// <summary>The timing test of the issue: 2 MiB at 256 KiB/s take about 8 seconds (wide tolerance); an unlimited user is not slowed.</summary>
    [Fact]
    [Trait("Category", "Slow")]
    public void A_user_limited_to_256_KiB_per_second_downloads_2_MiB_in_about_8_seconds()
    {
        var limitedRoot = _server.AddQuotaUser("bw-limited", u => u.Bandwidth = new BandwidthLimit { DownloadKiBPerSecond = 256 });
        var freeRoot = _server.AddQuotaUser("bw-free", _ => { });
        File.WriteAllBytes(Path.Combine(limitedRoot, "f.bin"), new byte[2048 * KiB]);
        File.WriteAllBytes(Path.Combine(freeRoot, "f.bin"), new byte[2048 * KiB]);

        var free = Time("bw-free");
        var limited = Time("bw-limited");

        Assert.InRange(limited.TotalSeconds, 6, 30);
        Assert.True(free < TimeSpan.FromSeconds(5), $"The unlimited user took {free}.");
    }

    private TimeSpan Time(string username)
    {
        using var client = _server.Connect(username);
        using var target = new MemoryStream();
        var watch = Stopwatch.StartNew();
        client.DownloadFile("/f.bin", target);
        watch.Stop();
        Assert.Equal(2048 * KiB, target.Length);
        return watch.Elapsed;
    }
}
