using System.Security.Cryptography;
using System.Text;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using SshServer.Filesystem.AzureBlob;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage.AzureBlob;

/// <summary>
/// The Azure requests of <see cref="AzureBlobFileSystem"/> against Azurite: the names below the prefix, the directory
/// markers, block blobs, abort, append, the options of new blobs and the sign-in with a connection string and a SAS URL.
/// The contract itself is in <see cref="AzuriteConformanceTests"/>. Skipped unless FREESFTPSHARP_TEST_AZURITE is set.
/// </summary>
[Trait("Category", "Azure")]
public sealed class AzureBlobFileSystemTests : IDisposable
{
    private const int KiB = 1024;
    private const FileOpenFlags WriteNew = FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate;

    private readonly string _prefix = "unit/" + Guid.NewGuid().ToString("N");

    public AzureBlobFileSystemTests()
    {
        AzuriteTestServer.SkipIfUnavailable();
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private AzureBlobFileSystem CreateFileSystem(int blockSize = 64 * KiB, string? tier = null, AzureBlobStorageOptions? options = null)
    {
        options ??= (AzuriteTestServer.Options(_prefix) with { UploadBlockSize = blockSize, AccessTier = tier, ReadAheadSize = 128 * KiB });
        return new AzureBlobFileSystem(AzuriteTestServer.Client, options);
    }

    public void Dispose()
    {
        if (AzuriteTestServer.Endpoint != null)
            AzuriteTestServer.DeletePrefix(_prefix);
    }

    private BlobClient Blob(string relative) => AzuriteTestServer.Client.GetBlobClient($"{_prefix}/{relative}");

    [Fact]
    public async Task Files_are_blobs_below_the_prefix_and_a_directory_is_a_marker_blob_with_hdi_isfolder()
    {
        var fs = CreateFileSystem();

        await fs.CreateDirectoryAsync("/dir", Ct);
        await WriteAsync(fs, "/dir/a.txt", "a"u8.ToArray());

        Assert.Equal([$"{_prefix}/dir", $"{_prefix}/dir/a.txt"], AzuriteTestServer.BlobNames(_prefix));
        var marker = (await Blob("dir").GetPropertiesAsync(cancellationToken: Ct)).Value;
        Assert.Equal(0, marker.ContentLength);
        Assert.Equal("true", marker.Metadata["hdi_isfolder"]);
        Assert.Equal("a"u8.ToArray(), (await Blob("dir/a.txt").DownloadContentAsync(Ct)).Value.Content.ToArray());
    }

    [Fact]
    public async Task Blobs_outside_the_prefix_are_not_visible()
    {
        await AzuriteTestServer.Client.GetBlobClient($"{_prefix}-other/secret.txt").UploadAsync(new MemoryStream("x"u8.ToArray()), overwrite: true, cancellationToken: Ct);
        try
        {
            var fs = CreateFileSystem();

            Assert.Empty(await ListAsync(fs, "/"));
            Assert.Null(await fs.StatAsync("/../" + Path.GetFileName(_prefix) + "-other/secret.txt", true, Ct));
        }
        finally
        {
            await AzuriteTestServer.Client.DeleteBlobIfExistsAsync($"{_prefix}-other/secret.txt", cancellationToken: Ct);
        }
    }

    [Fact]
    public async Task A_directory_without_a_marker_exists_while_it_has_blobs_and_is_listed_once_with_a_marker()
    {
        await Blob("plain/b.txt").UploadAsync(new MemoryStream("b"u8.ToArray()), overwrite: true, cancellationToken: Ct);
        var fs = CreateFileSystem();
        await fs.CreateDirectoryAsync("/marked", Ct);
        await WriteAsync(fs, "/marked/c.txt", "c"u8.ToArray());

        var entries = await ListAsync(fs, "/");

        Assert.Equal(["marked", "plain"], entries.Select(e => e.Name).Order(StringComparer.Ordinal));
        Assert.All(entries, e => Assert.True(e.IsDirectory));
        Assert.Equal(["b.txt"], (await ListAsync(fs, "/plain")).Select(e => e.Name));
    }

    [Fact]
    public async Task A_file_below_the_block_size_is_one_Put_Blob_and_a_larger_one_is_a_block_blob()
    {
        var fs = CreateFileSystem(blockSize: 64 * KiB);

        await WriteAsync(fs, "/small.bin", RandomNumberGenerator.GetBytes(10 * KiB));
        var big = RandomNumberGenerator.GetBytes(150 * KiB);
        await WriteAsync(fs, "/big.bin", big);

        Assert.Empty((await Block("small.bin").GetBlockListAsync(BlockListTypes.Committed, cancellationToken: Ct)).Value.CommittedBlocks);
        var blocks = (await Block("big.bin").GetBlockListAsync(BlockListTypes.Committed, cancellationToken: Ct)).Value.CommittedBlocks.ToList();
        Assert.Equal([64 * KiB, 64 * KiB, 22 * KiB], blocks.Select(b => b.SizeLong));
        Assert.Equal(big, (await Blob("big.bin").DownloadContentAsync(Ct)).Value.Content.ToArray());
    }

    [Fact]
    public async Task An_abort_after_blocks_were_sent_leaves_no_blob_and_no_visible_change()
    {
        var fs = CreateFileSystem(blockSize: 64 * KiB);
        await WriteAsync(fs, "/keep.bin", "old"u8.ToArray());
        var handle = await fs.OpenAsync("/a.bin", WriteNew, null, Ct);
        await handle.WriteAsync(0, RandomNumberGenerator.GetBytes(150 * KiB), Ct);
        await handle.FlushAsync(Ct);
        Assert.True(await AzuriteTestServer.CountUncommittedBlocksAsync($"{_prefix}/a.bin") >= 2, "The blocks are not staged.");

        await handle.AbortAsync();

        Assert.False((await Blob("a.bin").ExistsAsync(Ct)).Value);
        Assert.Equal([$"{_prefix}/keep.bin"], AzuriteTestServer.BlobNames(_prefix));
        await handle.DisposeAsync(); // does nothing
        Assert.False((await Blob("a.bin").ExistsAsync(Ct)).Value);
    }

    [Fact]
    public async Task An_abort_of_an_overwrite_keeps_the_old_content()
    {
        var fs = CreateFileSystem(blockSize: 64 * KiB);
        var old = RandomNumberGenerator.GetBytes(100 * KiB);
        await WriteAsync(fs, "/a.bin", old);
        var handle = await fs.OpenAsync("/a.bin", WriteNew, null, Ct);
        await handle.WriteAsync(0, RandomNumberGenerator.GetBytes(200 * KiB), Ct);
        await handle.FlushAsync(Ct);

        await handle.AbortAsync();

        Assert.Equal(old, (await Blob("a.bin").DownloadContentAsync(Ct)).Value.Content.ToArray());
    }

    [Fact]
    public async Task An_abort_of_a_small_or_new_empty_file_stores_nothing()
    {
        var fs = CreateFileSystem();
        var small = await fs.OpenAsync("/small.txt", WriteNew, null, Ct);
        await small.WriteAsync(0, "partial"u8.ToArray(), Ct);
        var empty = await fs.OpenAsync("/empty.txt", WriteNew, null, Ct);

        await small.AbortAsync();
        await empty.AbortAsync();

        Assert.Empty(AzuriteTestServer.BlobNames(_prefix));
    }

    [Fact]
    public async Task An_append_to_a_block_blob_keeps_its_blocks_and_adds_new_ones()
    {
        var fs = CreateFileSystem(blockSize: 64 * KiB);
        var first = RandomNumberGenerator.GetBytes(150 * KiB);
        var second = RandomNumberGenerator.GetBytes(100 * KiB);
        await WriteAsync(fs, "/a.bin", first);
        var before = (await Block("a.bin").GetBlockListAsync(BlockListTypes.Committed, cancellationToken: Ct)).Value.CommittedBlocks.Select(b => b.Name).ToList();

        var handle = await fs.OpenAsync("/a.bin", FileOpenFlags.Write | FileOpenFlags.Append, null, Ct);
        await handle.WriteAsync(0, second, Ct);
        await handle.DisposeAsync();

        var after = (await Block("a.bin").GetBlockListAsync(BlockListTypes.Committed, cancellationToken: Ct)).Value.CommittedBlocks.Select(b => b.Name).ToList();
        Assert.Equal(before, after.Take(before.Count)); // the old blocks were not sent again
        Assert.Equal(first.Concat(second).ToArray(), (await Blob("a.bin").DownloadContentAsync(Ct)).Value.Content.ToArray());
    }

    [Fact]
    public async Task An_append_to_a_blob_that_another_tool_wrote_reads_it_into_new_blocks()
    {
        var fs = CreateFileSystem(blockSize: 64 * KiB);
        var first = RandomNumberGenerator.GetBytes(150 * KiB);
        await Blob("a.bin").UploadAsync(new MemoryStream(first), overwrite: true, cancellationToken: Ct); // one Put Blob, no block list
        await Blob("small.bin").UploadAsync(new MemoryStream("abc"u8.ToArray()), overwrite: true, cancellationToken: Ct);

        foreach (var name in new[] { "a.bin", "small.bin" })
        {
            var handle = await fs.OpenAsync("/" + name, FileOpenFlags.Write | FileOpenFlags.Append, null, Ct);
            await handle.WriteAsync(0, "-end"u8.ToArray(), Ct);
            await handle.DisposeAsync();
        }

        Assert.Equal(first.Concat("-end"u8.ToArray()).ToArray(), (await Blob("a.bin").DownloadContentAsync(Ct)).Value.Content.ToArray());
        Assert.Equal("abc-end", Encoding.ASCII.GetString((await Blob("small.bin").DownloadContentAsync(Ct)).Value.Content.ToArray()));
    }

    [Fact]
    public async Task A_replaced_file_gives_a_failure_instead_of_mixed_content()
    {
        var fs = CreateFileSystem(blockSize: 64 * KiB);
        await WriteAsync(fs, "/a.bin", RandomNumberGenerator.GetBytes(500 * KiB)); // larger than the read-ahead
        await using var handle = await fs.OpenAsync("/a.bin", FileOpenFlags.Read, null, Ct);
        await Blob("a.bin").UploadAsync(new MemoryStream(RandomNumberGenerator.GetBytes(500 * KiB)), overwrite: true, cancellationToken: Ct);

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await handle.ReadAsync(400 * KiB, new byte[10], Ct));

        Assert.Equal(FileSystemError.Failure, ex.Error);
    }

    [Fact]
    public async Task The_access_tier_is_set_on_new_blobs_and_on_a_rename()
    {
        var fs = CreateFileSystem(blockSize: 64 * KiB, tier: "Cool");

        await WriteAsync(fs, "/small.bin", new byte[10]);
        await WriteAsync(fs, "/big.bin", RandomNumberGenerator.GetBytes(100 * KiB));
        await fs.RenameAsync("/small.bin", "/moved.bin", RenameFlags.None, Ct);

        foreach (var name in new[] { "moved.bin", "big.bin" })
            Assert.Equal(AccessTier.Cool, (await Blob(name).GetPropertiesAsync(cancellationToken: Ct)).Value.AccessTier);
    }

    [Fact]
    public async Task A_rename_copies_a_directory_with_its_marker_and_removes_the_source()
    {
        var fs = CreateFileSystem();
        await fs.CreateDirectoryAsync("/d", Ct);
        await fs.CreateDirectoryAsync("/d/empty", Ct);
        await WriteAsync(fs, "/d/a.txt", "a"u8.ToArray());

        await fs.RenameAsync("/d", "/e", RenameFlags.None, Ct);

        Assert.Equal([$"{_prefix}/e", $"{_prefix}/e/a.txt", $"{_prefix}/e/empty"], AzuriteTestServer.BlobNames(_prefix));
        Assert.Equal("true", (await Blob("e/empty").GetPropertiesAsync(cancellationToken: Ct)).Value.Metadata["hdi_isfolder"]);
    }

    [Fact]
    public async Task The_backend_works_with_a_connection_string_and_with_a_container_sas_url()
    {
        var options = new AzureBlobStorageOptions { SasUrl = AzuriteTestServer.SasUrl(), KeyPrefix = _prefix };
        var provider = new AzureBlobStorageProvider(new AzureBlobClientCache());
        var viaConnectionString = await provider.CreateAsync(AzuriteTestServer.Options(_prefix), Ct);
        var viaSas = await provider.CreateAsync(options, Ct);

        await WriteAsync(viaConnectionString, "/c.txt", "conn"u8.ToArray());
        await WriteAsync(viaSas, "/s.txt", "sas"u8.ToArray());

        Assert.Equal(["c.txt", "s.txt"], (await ListAsync(viaSas, "/")).Select(e => e.Name).Order(StringComparer.Ordinal));
        Assert.Equal(3, (await viaConnectionString.StatAsync("/s.txt", true, Ct))!.Size);
    }

    [Fact]
    public async Task A_missing_container_is_a_failure_and_not_a_missing_file()
    {
        var options = AzuriteTestServer.Options(_prefix) with { Container = "no-such-container-" + Guid.NewGuid().ToString("N").Substring(0, 8) };
        var fs = new AzureBlobFileSystem(new AzureBlobClientCache().Get(options), options);

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await fs.StatAsync("/a.txt", true, Ct));

        Assert.Equal(FileSystemError.Failure, ex.Error);
        Assert.DoesNotContain(options.Container, ex.Message);
    }

    [Fact]
    public async Task A_bad_key_is_a_permission_denied_and_leaks_neither_the_account_nor_the_container()
    {
        var options = AzuriteTestServer.Options(_prefix) with
        {
            ConnectionString = AzuriteTestServer.ConnectionString.Replace("Eby8", "Fby8"),
        };
        var fs = new AzureBlobFileSystem(new AzureBlobClientCache().Get(options), options);

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await fs.StatAsync("/a.txt", true, Ct));

        Assert.Equal(FileSystemError.PermissionDenied, ex.Error);
        Assert.DoesNotContain(AzuriteTestServer.AccountName, ex.Message);
        Assert.DoesNotContain(AzuriteTestServer.Container, ex.Message);
    }

    private Azure.Storage.Blobs.Specialized.BlockBlobClient Block(string relative)
        => AzuriteTestServer.Client.GetBlockBlobClient($"{_prefix}/{relative}");

    private static async Task WriteAsync(IFileSystem fs, string path, byte[] data)
    {
        await using var handle = await fs.OpenAsync(path, WriteNew, null, Ct);
        await handle.WriteAsync(0, data, Ct);
    }

    private static async Task<List<FileSystemEntry>> ListAsync(IFileSystem fs, string path)
    {
        var entries = new List<FileSystemEntry>();
        await foreach (var entry in fs.ListAsync(path, Ct))
            entries.Add(entry);
        return entries;
    }
}
