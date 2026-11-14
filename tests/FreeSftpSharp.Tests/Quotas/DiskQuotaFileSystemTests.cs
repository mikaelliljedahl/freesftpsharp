using FreeSftpSharp.Tests.Storage;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;
using SshServerModule.Quotas;

namespace FreeSftpSharp.Tests.Quotas;

/// <summary><see cref="DiskQuotaFileSystem"/> over <see cref="InMemoryFileSystem"/>: what is counted, what is refused, and that a refused upload leaves nothing.</summary>
public sealed class DiskQuotaFileSystemTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly QuotaScope Scope = QuotaScope.ForUser("alice");

    private readonly InMemoryFileSystem _backend = new();
    private readonly QuotaUsageTracker _tracker = new(new InMemoryQuotaUsageStore());

    private IFileSystem Create(long maxBytes = 0, long maxFiles = 0, IFileSystem? inner = null)
        => new DiskQuotaFileSystem(inner ?? _backend, _tracker, Scope, new DiskQuota { MaxSizeBytes = maxBytes, MaxFiles = maxFiles });

    private QuotaUsage Usage => _tracker.Current(Scope);

    private static async Task UploadAsync(IFileSystem fs, string path, int size, int chunk = 1000)
    {
        await using var handle = await fs.OpenAsync(path, FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate, null, Ct);
        for (var offset = 0; offset < size; offset += chunk)
            await handle.WriteAsync(offset, new byte[Math.Min(chunk, size - offset)], Ct);
    }

    private static async Task<FileSystemException> UploadFailsAsync(IFileSystem fs, string path, int size, int chunk = 1000)
    {
        var handle = await fs.OpenAsync(path, FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate, null, Ct);
        try
        {
            for (var offset = 0; offset < size; offset += chunk)
                await handle.WriteAsync(offset, new byte[Math.Min(chunk, size - offset)], Ct);
        }
        catch (FileSystemException ex)
        {
            return ex;
        }
        finally
        {
            await handle.DisposeAsync();
        }
        throw new Xunit.Sdk.XunitException("The upload did not fail.");
    }

    [Fact]
    public void Wrap_leaves_out_the_decorator_without_a_limit()
    {
        Assert.Same(_backend, DiskQuotaFileSystem.Wrap(_backend, _tracker, Scope, null));
        Assert.Same(_backend, DiskQuotaFileSystem.Wrap(_backend, _tracker, Scope, new DiskQuota()));
        Assert.IsType<DiskQuotaFileSystem>(DiskQuotaFileSystem.Wrap(_backend, _tracker, Scope, new DiskQuota { MaxFiles = 1 }));
    }

    [Fact]
    public async Task An_upload_counts_its_size_and_one_file()
    {
        var fs = Create(maxBytes: 10_000);

        await UploadAsync(fs, "/a.bin", 4_500);

        Assert.Equal(4_500, Usage.UsedBytes);
        Assert.Equal(1, Usage.UsedFiles);
    }

    [Fact]
    public async Task An_upload_over_the_quota_fails_and_leaves_no_partial_file_and_no_counter_drift()
    {
        var fs = Create(maxBytes: 10_000);
        await UploadAsync(fs, "/first.bin", 9_000);

        var ex = await UploadFailsAsync(fs, "/second.bin", 2_000);

        Assert.Equal(FileSystemError.QuotaExceeded, ex.Error);
        Assert.Null(await _backend.StatAsync("/second.bin", true, Ct));
        Assert.Equal(9_000, Usage.UsedBytes);
        Assert.Equal(1, Usage.UsedFiles);

        await fs.DeleteFileAsync("/first.bin", Ct);
        await UploadAsync(fs, "/second.bin", 2_000);
        Assert.Equal(2_000, Usage.UsedBytes);
        Assert.Equal(1, Usage.UsedFiles);
    }

    [Fact]
    public async Task One_large_write_cannot_go_over_the_limit()
    {
        var fs = Create(maxBytes: 1_000);
        await using var handle = await fs.OpenAsync("/big.bin", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct);

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await handle.WriteAsync(0, new byte[1_001], Ct));
        Assert.Equal(FileSystemError.QuotaExceeded, ex.Error);
        Assert.Equal(0, (await _backend.StatAsync("/big.bin", true, Ct))!.Size); // nothing reached the storage

        // A refused handle refuses every later write too, also a small one.
        await Assert.ThrowsAsync<FileSystemException>(async () => await handle.WriteAsync(0, new byte[1], Ct));
    }

    [Fact]
    public async Task A_full_quota_refuses_to_create_a_file()
    {
        var fs = Create(maxBytes: 1_000);
        await UploadAsync(fs, "/full.bin", 1_000);

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await fs.OpenAsync("/more.bin", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct));

        Assert.Equal(FileSystemError.QuotaExceeded, ex.Error);
        Assert.Null(await _backend.StatAsync("/more.bin", true, Ct));
        Assert.Equal(1, Usage.UsedFiles);
    }

    [Fact]
    public async Task Overwriting_a_file_with_truncate_releases_its_old_size_first()
    {
        var fs = Create(maxBytes: 1_000);
        await UploadAsync(fs, "/f.bin", 900);

        await UploadAsync(fs, "/f.bin", 800); // fits only because the old 900 bytes are released

        Assert.Equal(800, Usage.UsedBytes);
        Assert.Equal(1, Usage.UsedFiles);
    }

    [Fact]
    public async Task The_number_of_files_is_limited_and_a_failed_open_releases_its_reservation()
    {
        var fs = Create(maxFiles: 2);
        await UploadAsync(fs, "/1", 10);
        await Assert.ThrowsAsync<FileSystemException>(async () => await fs.OpenAsync("/missing-dir/2", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct));
        await UploadAsync(fs, "/2", 10);

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await fs.OpenAsync("/3", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct));

        Assert.Equal(FileSystemError.QuotaExceeded, ex.Error);
        Assert.Equal(2, Usage.UsedFiles);
        await UploadAsync(fs, "/2", 20); // an existing file can still be written
        Assert.Equal(30, Usage.UsedBytes);
    }

    [Fact]
    public async Task Delete_and_a_replacing_rename_release_the_file()
    {
        var fs = Create(maxBytes: 10_000);
        await UploadAsync(fs, "/a", 100);
        await UploadAsync(fs, "/b", 200);
        await UploadAsync(fs, "/c", 300);

        await fs.RenameAsync("/a", "/b", RenameFlags.ReplaceExisting, Ct);
        Assert.Equal((400L, 2L), (Usage.UsedBytes, Usage.UsedFiles));

        await fs.RenameAsync("/b", "/d", RenameFlags.None, Ct);
        Assert.Equal((400L, 2L), (Usage.UsedBytes, Usage.UsedFiles));

        await fs.DeleteFileAsync("/c", Ct);
        Assert.Equal((100L, 1L), (Usage.UsedBytes, Usage.UsedFiles));
    }

    [Fact]
    public async Task A_failed_delete_changes_nothing()
    {
        var fs = Create(maxBytes: 10_000);
        await UploadAsync(fs, "/a", 100);
        await _backend.CreateDirectoryAsync("/dir", Ct);

        await Assert.ThrowsAsync<FileSystemException>(async () => await fs.DeleteFileAsync("/missing", Ct));
        await Assert.ThrowsAsync<FileSystemException>(async () => await fs.DeleteFileAsync("/dir", Ct));

        Assert.Equal((100L, 1L), (Usage.UsedBytes, Usage.UsedFiles));
    }

    [Fact]
    public async Task A_size_change_by_setstat_is_checked_and_counted()
    {
        var fs = Create(maxBytes: 1_000);
        await UploadAsync(fs, "/f", 500);

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await fs.SetAttributesAsync("/f", new FileAttributesUpdate { Size = 1_001 }, Ct));
        Assert.Equal(FileSystemError.QuotaExceeded, ex.Error);
        Assert.Equal(500, (await _backend.StatAsync("/f", true, Ct))!.Size);

        await fs.SetAttributesAsync("/f", new FileAttributesUpdate { Size = 1_000 }, Ct);
        Assert.Equal(1_000, Usage.UsedBytes);

        await using (var handle = await fs.OpenAsync("/f", FileOpenFlags.Write, null, Ct))
            await handle.SetAttributesAsync(new FileAttributesUpdate { Size = 200 }, Ct);
        Assert.Equal(200, Usage.UsedBytes);
    }

    [Fact]
    public async Task Writes_inside_the_file_and_appends_count_only_the_growth()
    {
        var fs = Create(maxBytes: 10_000);
        await UploadAsync(fs, "/f", 1_000);

        await using (var handle = await fs.OpenAsync("/f", FileOpenFlags.Write, null, Ct))
        {
            await handle.WriteAsync(0, new byte[500], Ct);  // inside
            await handle.WriteAsync(900, new byte[200], Ct); // 100 bytes past the end
        }
        Assert.Equal(1_100, Usage.UsedBytes);

        await using (var handle = await fs.OpenAsync("/f", FileOpenFlags.Write | FileOpenFlags.Append, null, Ct))
            await handle.WriteAsync(0, new byte[50], Ct);
        Assert.Equal(1_150, Usage.UsedBytes);
        Assert.Equal(1_150, (await _backend.StatAsync("/f", true, Ct))!.Size);
    }

    [Fact]
    public async Task A_lost_session_counts_what_the_storage_kept()
    {
        var spy = new AbortSpyFileSystem(_backend);
        var fs = Create(maxBytes: 10_000, inner: spy);
        var handle = await fs.OpenAsync("/partial", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct);
        await handle.WriteAsync(0, new byte[700], Ct);

        await handle.AbortAsync();

        Assert.Equal(["Abort"], spy.Closes);
        Assert.Equal(700, (await _backend.StatAsync("/partial", true, Ct))!.Size); // the in-memory storage keeps partial data, like a disk
        Assert.Equal((700L, 1L), (Usage.UsedBytes, Usage.UsedFiles));
    }

    [Fact]
    public async Task A_refused_upload_is_aborted_in_the_storage()
    {
        var spy = new AbortSpyFileSystem(_backend);
        var fs = Create(maxBytes: 100, inner: spy);

        await UploadFailsAsync(fs, "/x", 200, chunk: 60);

        Assert.Equal(["Abort"], spy.Closes);
        Assert.Null(await _backend.StatAsync("/x", true, Ct));
        Assert.Equal((0L, 0L), (Usage.UsedBytes, Usage.UsedFiles));
    }

    [Fact]
    public async Task The_storage_space_is_the_quota()
    {
        var fs = Create(maxBytes: 8_192);
        await UploadAsync(fs, "/f", 4_096);

        var space = await fs.GetStorageSpaceAsync("/", Ct);

        Assert.NotNull(space);
        Assert.Equal(8_192UL, space.TotalBytes);
        Assert.Equal(4_096UL, space.FreeBytes);
        Assert.Equal(4_096UL, space.AvailableBytes);
    }

    [Fact]
    public async Task Reading_is_not_counted()
    {
        var fs = Create(maxBytes: 1_000);
        await UploadAsync(fs, "/f", 100);

        await using (var handle = await fs.OpenAsync("/f", FileOpenFlags.Read, null, Ct))
            Assert.Equal(100, await handle.ReadAsync(0, new byte[200], Ct));

        Assert.Equal((100L, 1L), (Usage.UsedBytes, Usage.UsedFiles));
    }
}

/// <summary>The conformance suite through <see cref="DiskQuotaFileSystem"/> with a quota that is never reached: the decorator must be invisible.</summary>
public sealed class DiskQuotaFileSystemConformanceTests : FileSystemConformanceTests<DiskQuotaFileSystemConformanceTests.Fixture>
{
    public sealed class Fixture : IFileSystemFixture
    {
        public IFileSystem FileSystem { get; } = new DiskQuotaFileSystem(new InMemoryFileSystem(), new QuotaUsageTracker(new InMemoryQuotaUsageStore()),
            QuotaScope.ForUser("conformance"), new DiskQuota { MaxSizeBytes = long.MaxValue / 2, MaxFiles = 1_000_000 });

        public StorageCapabilities ExpectedCapabilities => InMemoryFileSystem.AllCapabilities;

        public void Dispose() { }
    }
}
