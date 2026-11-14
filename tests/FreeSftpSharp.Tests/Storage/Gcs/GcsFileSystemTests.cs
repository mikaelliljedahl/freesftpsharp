using System.Security.Cryptography;
using SshServer.Filesystem.Gcs;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage.Gcs;

/// <summary>
/// The behaviour of <see cref="GcsFileSystem"/> that the conformance suite does not cover (resumable uploads in chunks,
/// append by compose, abort), against the emulator. Skipped unless FREESFTPSHARP_TEST_GCS_ENDPOINT is set.
/// </summary>
[Trait("Category", "Gcs")]
public sealed class GcsFileSystemTests : IDisposable
{
    private const int KiB = 1024;
    private const int Chunk = 256 * KiB;
    private const FileOpenFlags WriteNew = FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate;

    private readonly string _prefix = "unit/" + Guid.NewGuid().ToString("N");
    private readonly GcsFileSystem _fs;

    public GcsFileSystemTests()
    {
        GcsTestServer.SkipIfUnavailable();
        _fs = new GcsFileSystem(GcsTestServer.Client, GcsTestServer.Options(_prefix) with { UploadChunkSize = Chunk });
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        if (GcsTestServer.Endpoint != null)
            GcsTestServer.DeletePrefix(_prefix);
    }

    [Fact]
    public async Task A_file_of_many_chunks_is_uploaded_resumably_and_reads_back_the_same()
    {
        var content = RandomNumberGenerator.GetBytes(Chunk * 3 + 12345);
        await WriteAsync("/big.bin", content, 100 * KiB);

        Assert.Equal(content.Length, (await _fs.StatAsync("/big.bin", true, Ct))!.Size);
        Assert.Equal(content, await ReadAsync("/big.bin"));
        Assert.Equal([_prefix + "/big.bin"], GcsTestServer.ObjectNames(_prefix));
    }

    [Fact]
    public async Task A_file_of_exactly_whole_chunks_is_complete()
    {
        var content = RandomNumberGenerator.GetBytes(Chunk * 2);
        await WriteAsync("/exact.bin", content, Chunk);

        Assert.Equal(content, await ReadAsync("/exact.bin"));
    }

    [Fact]
    public async Task A_write_at_the_end_of_a_large_file_is_joined_by_compose_and_leaves_no_temporary_object()
    {
        var first = RandomNumberGenerator.GetBytes(Chunk * 2 + 10);
        var second = RandomNumberGenerator.GetBytes(Chunk + 77);
        await WriteAsync("/a.bin", first, Chunk);

        await using (var handle = await _fs.OpenAsync("/a.bin", FileOpenFlags.Write, null, Ct))
            await handle.WriteAsync(first.Length, second, Ct);

        var expected = first.Concat(second).ToArray();
        Assert.Equal(expected, await ReadAsync("/a.bin"));
        Assert.Equal([_prefix + "/a.bin"], GcsTestServer.ObjectNames(_prefix));
    }

    [Fact]
    public async Task A_small_append_to_a_large_file_is_joined_by_compose()
    {
        var first = RandomNumberGenerator.GetBytes(Chunk + 5);
        await WriteAsync("/a.bin", first, Chunk);

        await using (var handle = await _fs.OpenAsync("/a.bin", FileOpenFlags.Write | FileOpenFlags.Append, null, Ct))
            await handle.WriteAsync(0, "tail"u8.ToArray(), Ct);

        var expected = first.Concat("tail"u8.ToArray()).ToArray();
        Assert.Equal(expected, await ReadAsync("/a.bin"));
        Assert.Equal([_prefix + "/a.bin"], GcsTestServer.ObjectNames(_prefix));
    }

    [Fact]
    public async Task An_abort_after_chunks_were_sent_finalizes_nothing()
    {
        var handle = await _fs.OpenAsync("/a.bin", WriteNew, null, Ct);
        await handle.WriteAsync(0, RandomNumberGenerator.GetBytes(Chunk * 2 + 100), Ct);
        await handle.FlushAsync(Ct);

        await handle.AbortAsync();

        Assert.Empty(GcsTestServer.ObjectNames(_prefix));
        await handle.DisposeAsync(); // does nothing
        Assert.Empty(GcsTestServer.ObjectNames(_prefix));
    }

    [Fact]
    public async Task An_abort_of_a_small_file_or_a_new_file_without_data_stores_nothing()
    {
        var small = await _fs.OpenAsync("/small.txt", WriteNew, null, Ct);
        await small.WriteAsync(0, "partial"u8.ToArray(), Ct);
        await small.AbortAsync();
        var empty = await _fs.OpenAsync("/empty.txt", WriteNew, null, Ct);
        await empty.AbortAsync();

        Assert.Empty(GcsTestServer.ObjectNames(_prefix));
    }

    [Fact]
    public async Task An_abort_of_an_overwrite_keeps_the_old_object()
    {
        await WriteAsync("/a.bin", "old"u8.ToArray(), 10);
        var handle = await _fs.OpenAsync("/a.bin", WriteNew, null, Ct);
        await handle.WriteAsync(0, RandomNumberGenerator.GetBytes(Chunk * 2), Ct);

        await handle.AbortAsync();

        Assert.Equal("old"u8.ToArray(), await ReadAsync("/a.bin"));
    }

    [Fact]
    public async Task An_abort_of_an_append_to_a_large_file_keeps_the_object_and_leaves_no_temporary_object()
    {
        var first = RandomNumberGenerator.GetBytes(Chunk + 5);
        await WriteAsync("/a.bin", first, Chunk);
        var handle = await _fs.OpenAsync("/a.bin", FileOpenFlags.Write, null, Ct);
        await handle.WriteAsync(first.Length, RandomNumberGenerator.GetBytes(Chunk * 2), Ct);

        await handle.AbortAsync();

        Assert.Equal(first, await ReadAsync("/a.bin"));
        Assert.Equal([_prefix + "/a.bin"], GcsTestServer.ObjectNames(_prefix));
    }

    [Fact]
    public async Task An_exclusive_create_loses_against_a_file_that_appears_before_the_close()
    {
        var handle = await _fs.OpenAsync("/race.txt", FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Exclusive, null, Ct);
        await handle.WriteAsync(0, "mine"u8.ToArray(), Ct);
        await WriteAsync("/race.txt", "theirs"u8.ToArray(), 10);

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await handle.DisposeAsync());

        Assert.Equal(FileSystemError.AlreadyExists, ex.Error);
        Assert.Equal("theirs"u8.ToArray(), await ReadAsync("/race.txt"));
    }

    [Fact]
    public async Task The_storage_class_is_set_on_new_objects()
    {
        var fs = new GcsFileSystem(GcsTestServer.Client, GcsTestServer.Options(_prefix) with { StorageClass = "NEARLINE", UploadChunkSize = Chunk });
        await using (var handle = await fs.OpenAsync("/c.txt", WriteNew, null, Ct))
            await handle.WriteAsync(0, "x"u8.ToArray(), Ct);

        Assert.Equal("NEARLINE", GcsTestServer.Client.GetObject(GcsTestServer.Bucket, _prefix + "/c.txt").StorageClass);
    }

    private async Task WriteAsync(string path, byte[] content, int piece)
    {
        await using var handle = await _fs.OpenAsync(path, WriteNew, null, Ct);
        for (var offset = 0; offset < content.Length; offset += piece)
            await handle.WriteAsync(offset, content.AsMemory(offset, Math.Min(piece, content.Length - offset)), Ct);
    }

    private async Task<byte[]> ReadAsync(string path)
    {
        await using var handle = await _fs.OpenAsync(path, FileOpenFlags.Read, null, Ct);
        var size = (await handle.StatAsync(Ct)).Size;
        var buffer = new byte[size];
        var read = 0;
        while (read < size)
        {
            var n = await handle.ReadAsync(read, buffer.AsMemory(read, (int)Math.Min(100 * KiB, size - read)), Ct);
            Assert.True(n > 0);
            read += n;
        }
        return buffer;
    }
}
