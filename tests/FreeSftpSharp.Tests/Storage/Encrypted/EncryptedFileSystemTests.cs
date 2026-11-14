using System.Security.Cryptography;
using SshServer.Filesystem.Encrypted;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage.Encrypted;

/// <summary>
/// <see cref="EncryptedFileSystem"/> on a temporary directory: what is on the disk, reads at any offset, damaged and
/// changed files (always <see cref="FileSystemError.Failure"/>, never wrong bytes), key rotation and the operations the
/// format does not allow.
/// </summary>
public sealed class EncryptedFileSystemTests : IDisposable
{
    private const FileOpenFlags WriteNew = FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate;
    private const int Chunk = 65_536;
    private const int EncryptedChunk = 65_552;
    private const int Header = 53;

    private readonly string _root = Path.Combine(Path.GetTempPath(), "freesftpsharp-tests", Guid.NewGuid().ToString("N"));

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public EncryptedFileSystemTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    // ---- On the disk ----

    [Fact]
    public async Task The_file_on_disk_has_the_header_and_not_the_plaintext()
    {
        var content = System.Text.Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("secret plaintext ", 10_000)));
        await WriteAsync(CreateFileSystem(), "/a.txt", content);

        var onDisk = File.ReadAllBytes(PhysicalPath("/a.txt"));

        Assert.Equal("FSS1"u8.ToArray(), onDisk[..4]);
        Assert.Equal(1, onDisk[4]);
        Assert.Equal(new MasterKey("a", TestKeys.KeyA).KeyId.ToArray(), onDisk[5..21]);
        Assert.Equal(EncryptedFileFormat.FileSize(content.Length), onDisk.Length);
        Assert.Equal(-1, onDisk.AsSpan().IndexOf("secret"u8));
        Assert.Equal(content, await ReadAsync(CreateFileSystem(), "/a.txt"));
    }

    [Fact]
    public async Task Two_files_with_the_same_content_have_different_bytes_on_disk()
    {
        var content = RandomNumberGenerator.GetBytes(1000);
        await WriteAsync(CreateFileSystem(), "/a", content);
        await WriteAsync(CreateFileSystem(), "/b", content);

        Assert.NotEqual(File.ReadAllBytes(PhysicalPath("/a")), File.ReadAllBytes(PhysicalPath("/b")));
    }

    [Fact]
    public async Task Stat_and_list_give_the_plaintext_size()
    {
        var fs = CreateFileSystem();
        await fs.CreateDirectoryAsync("/dir", Ct);
        await WriteAsync(fs, "/dir/a", new byte[140_000]);

        Assert.Equal(140_000, (await fs.StatAsync("/dir/a", true, Ct))!.Size);
        await foreach (var entry in fs.ListAsync("/dir", Ct))
            Assert.Equal(140_000, entry.Size);
        Assert.Equal(140_101, new FileInfo(PhysicalPath("/dir/a")).Length);
    }

    // ---- Reads at any offset ----

    [Fact]
    public async Task Reads_at_any_offset_give_the_same_bytes_as_the_plaintext()
    {
        var content = RandomNumberGenerator.GetBytes(3 * Chunk + 1234);
        var fs = CreateFileSystem();
        await WriteAsync(fs, "/a.bin", content);
        var random = new Random(52);

        await using var handle = await fs.OpenAsync("/a.bin", FileOpenFlags.Read, null, Ct);
        long[] edges = [0, 1, Chunk - 1, Chunk, Chunk + 1, 2 * Chunk - 7, 3 * Chunk, content.Length - 1, content.Length, content.Length + 5];
        foreach (var offset in edges.Concat(Enumerable.Range(0, 200).Select(_ => (long)random.Next(content.Length))))
        {
            var buffer = new byte[random.Next(1, 3 * Chunk)];
            var read = await handle.ReadAsync(offset, buffer, Ct);

            var expected = Math.Max(0, Math.Min(buffer.Length, content.Length - offset));
            Assert.Equal(expected, read);
            Assert.True(content.AsSpan((int)Math.Min(offset, content.Length), read).SequenceEqual(buffer.AsSpan(0, read)), $"offset {offset}");
        }
    }

    [Fact]
    public async Task A_writing_handle_reads_what_it_wrote_before_the_close()
    {
        var content = RandomNumberGenerator.GetBytes(Chunk + 100);
        await using var handle = await CreateFileSystem().OpenAsync("/a.bin", FileOpenFlags.Read | WriteNew, null, Ct);
        await handle.WriteAsync(0, content, Ct);

        var buffer = new byte[200];
        Assert.Equal(200, await handle.ReadAsync(Chunk - 100, buffer, Ct)); // across the chunk on disk and the one in memory
        Assert.True(content.AsSpan(Chunk - 100, 200).SequenceEqual(buffer));
    }

    // ---- Damaged and changed files ----

    public static TheoryData<string, int> FlippedBytes => new()
    {
        { "magic", 0 },
        { "version", 4 },
        { "key id", 10 },
        { "salt", 30 },
        { "first chunk", Header + 5 },
        { "tag of the first chunk", Header + Chunk + 3 },
        { "second chunk", Header + EncryptedChunk + 100 },
        { "last chunk", Header + 2 * EncryptedChunk + 1 },
        { "tag of the last chunk", -1 },
    };

    [Theory]
    [MemberData(nameof(FlippedBytes))]
    public async Task A_flipped_byte_gives_failure(string where, int position)
    {
        _ = where;
        await WriteAsync(CreateFileSystem(), "/a.bin", RandomNumberGenerator.GetBytes(2 * Chunk + 500));
        var bytes = File.ReadAllBytes(PhysicalPath("/a.bin"));
        bytes[position < 0 ? bytes.Length + position : position] ^= 0x01;
        File.WriteAllBytes(PhysicalPath("/a.bin"), bytes);

        await AssertFailureAsync(() => ReadAsync(CreateFileSystem(), "/a.bin"));
    }

    [Fact]
    public async Task Swapped_chunks_give_failure()
    {
        await WriteAsync(CreateFileSystem(), "/a.bin", RandomNumberGenerator.GetBytes(2 * Chunk + 500));
        var bytes = File.ReadAllBytes(PhysicalPath("/a.bin"));
        var first = bytes.AsSpan(Header, EncryptedChunk).ToArray();
        bytes.AsSpan(Header + EncryptedChunk, EncryptedChunk).CopyTo(bytes.AsSpan(Header));
        first.CopyTo(bytes.AsSpan(Header + EncryptedChunk));
        File.WriteAllBytes(PhysicalPath("/a.bin"), bytes);

        await AssertFailureAsync(() => ReadAsync(CreateFileSystem(), "/a.bin"));
    }

    [Fact]
    public async Task A_chunk_from_another_file_gives_failure()
    {
        var content = RandomNumberGenerator.GetBytes(2 * Chunk + 500);
        await WriteAsync(CreateFileSystem(), "/a.bin", content);
        await WriteAsync(CreateFileSystem(), "/b.bin", content);
        var a = File.ReadAllBytes(PhysicalPath("/a.bin"));
        var b = File.ReadAllBytes(PhysicalPath("/b.bin"));
        b.AsSpan(Header, EncryptedChunk).CopyTo(a.AsSpan(Header));
        File.WriteAllBytes(PhysicalPath("/a.bin"), a);

        await AssertFailureAsync(() => ReadAsync(CreateFileSystem(), "/a.bin"));
    }

    [Theory]
    [InlineData(0)] // empty file
    [InlineData(Header - 1)] // part of the header
    [InlineData(Header)] // header only
    [InlineData(Header + 100)] // inside the first chunk
    [InlineData(Header + EncryptedChunk)] // at a chunk boundary: the last chunk is full
    [InlineData(Header + 2 * EncryptedChunk)] // at the last chunk boundary
    [InlineData(Header + 2 * EncryptedChunk + 17)] // inside the last chunk
    [InlineData(-1)] // one byte of the last tag
    public async Task A_cut_file_gives_failure(int length)
    {
        await WriteAsync(CreateFileSystem(), "/a.bin", RandomNumberGenerator.GetBytes(2 * Chunk + 500));
        using (var stream = new FileStream(PhysicalPath("/a.bin"), FileMode.Open))
            stream.SetLength(length < 0 ? stream.Length + length : length);

        await AssertFailureAsync(() => ReadAsync(CreateFileSystem(), "/a.bin"));
    }

    [Fact]
    public async Task Removing_the_empty_last_chunk_gives_failure()
    {
        await WriteAsync(CreateFileSystem(), "/a.bin", RandomNumberGenerator.GetBytes(2 * Chunk));
        using (var stream = new FileStream(PhysicalPath("/a.bin"), FileMode.Open))
            stream.SetLength(stream.Length - 16);

        await AssertFailureAsync(() => ReadAsync(CreateFileSystem(), "/a.bin"));
    }

    [Fact]
    public async Task Appended_bytes_give_failure()
    {
        await WriteAsync(CreateFileSystem(), "/a.bin", RandomNumberGenerator.GetBytes(Chunk + 10));
        File.AppendAllText(PhysicalPath("/a.bin"), "more");

        await AssertFailureAsync(() => ReadAsync(CreateFileSystem(), "/a.bin"));
    }

    [Fact]
    public async Task A_plaintext_file_gives_failure()
    {
        File.WriteAllText(PhysicalPath("/plain.txt"), "This file was put on the disk without encryption, it is longer than a header.");

        await AssertFailureAsync(() => ReadAsync(CreateFileSystem(), "/plain.txt"));
    }

    [Fact]
    public async Task The_failure_message_has_the_virtual_path_and_no_key()
    {
        await WriteAsync(CreateFileSystem(), "/a.bin", new byte[10]);
        var bytes = File.ReadAllBytes(PhysicalPath("/a.bin"));
        bytes[^1] ^= 1;
        File.WriteAllBytes(PhysicalPath("/a.bin"), bytes);

        var ex = await Assert.ThrowsAsync<FileSystemException>(() => ReadAsync(CreateFileSystem(), "/a.bin"));

        Assert.Contains("/a.bin", ex.Message);
        Assert.DoesNotContain(_root, ex.Message);
        Assert.DoesNotContain(Convert.ToBase64String(TestKeys.KeyA), ex.Message);
    }

    // ---- Keys ----

    [Fact]
    public async Task A_file_written_with_key_a_is_readable_after_key_b_becomes_the_active_key()
    {
        var content = RandomNumberGenerator.GetBytes(Chunk + 7);
        await WriteAsync(CreateFileSystem(TestKeys.Provider("a", ("a", TestKeys.KeyA))), "/old.bin", content);

        var rotated = CreateFileSystem(TestKeys.Provider("b", ("a", TestKeys.KeyA), ("b", TestKeys.KeyB)));
        await WriteAsync(rotated, "/new.bin", content);

        Assert.Equal(content, await ReadAsync(rotated, "/old.bin"));
        Assert.Equal(content, await ReadAsync(rotated, "/new.bin"));
        Assert.Equal(new MasterKey("a", TestKeys.KeyA).KeyId.ToArray(), File.ReadAllBytes(PhysicalPath("/old.bin"))[5..21]);
        Assert.Equal(new MasterKey("b", TestKeys.KeyB).KeyId.ToArray(), File.ReadAllBytes(PhysicalPath("/new.bin"))[5..21]);
    }

    [Fact]
    public async Task A_file_of_a_key_that_is_not_configured_gives_failure()
    {
        await WriteAsync(CreateFileSystem(TestKeys.Provider("a", ("a", TestKeys.KeyA))), "/a.bin", new byte[10]);

        var ex = await Assert.ThrowsAsync<FileSystemException>(() => ReadAsync(CreateFileSystem(TestKeys.Provider("b", ("b", TestKeys.KeyB))), "/a.bin"));

        Assert.Equal(FileSystemError.Failure, ex.Error);
        Assert.Contains("key", ex.Message);
    }

    [Fact]
    public async Task Another_key_with_the_same_id_gives_failure()
    {
        await WriteAsync(CreateFileSystem(TestKeys.Provider("a", ("a", TestKeys.KeyA))), "/a.bin", new byte[10]);

        await AssertFailureAsync(() => ReadAsync(CreateFileSystem(TestKeys.Provider("a", ("a", TestKeys.KeyB))), "/a.bin"));
    }

    // ---- What the format does not allow ----

    [Fact]
    public void Capabilities_are_those_of_the_inner_storage_without_random_write_append_and_copy()
    {
        const StorageCapabilities notByTheFormat = StorageCapabilities.RandomAccessWrite | StorageCapabilities.Append | StorageCapabilities.ServerSideCopy;
        Assert.Equal(new LocalFileSystem(_root).Capabilities & ~notByTheFormat, CreateFileSystem().Capabilities);
        Assert.Equal(StorageCapabilities.Rename,
            new EncryptedFileSystem(new InMemoryFileSystem(StorageCapabilities.Rename | StorageCapabilities.RandomAccessWrite | StorageCapabilities.Append),
                TestKeys.Provider("a", ("a", TestKeys.KeyA))).Capabilities);
    }

    [Fact]
    public void Case_insensitive_paths_of_the_inner_storage_pass_through()
    {
        // The names are not encrypted, so the inner storage compares them; the permission decorator must know it.
        var keys = TestKeys.Provider("a", ("a", TestKeys.KeyA));

        Assert.True(new EncryptedFileSystem(new CapabilitiesOnly(StorageCapabilities.CaseInsensitivePaths | StorageCapabilities.Rename), keys)
            .Capabilities.HasFlag(StorageCapabilities.CaseInsensitivePaths));
        Assert.False(new EncryptedFileSystem(new CapabilitiesOnly(StorageCapabilities.Rename), keys)
            .Capabilities.HasFlag(StorageCapabilities.CaseInsensitivePaths));
    }

    /// <summary>A storage that only declares capabilities (the test reads nothing else).</summary>
    private sealed class CapabilitiesOnly(StorageCapabilities capabilities) : IFileSystem
    {
        public StorageCapabilities Capabilities => capabilities;
        public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct) => throw new NotSupportedException();
        public IAsyncEnumerable<FileSystemEntry> ListAsync(string path, CancellationToken ct) => throw new NotSupportedException();
        public ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct) => throw new NotSupportedException();
        public ValueTask CreateDirectoryAsync(string path, CancellationToken ct) => throw new NotSupportedException();
        public ValueTask DeleteFileAsync(string path, CancellationToken ct) => throw new NotSupportedException();
        public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct) => throw new NotSupportedException();
        public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct) => throw new NotSupportedException();
        public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct) => throw new NotSupportedException();
        public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct) => throw new NotSupportedException();
    }

    [Fact]
    public async Task A_write_to_an_existing_file_without_truncate_is_not_supported_and_changes_nothing()
    {
        var fs = CreateFileSystem();
        await WriteAsync(fs, "/a.txt", "abc"u8.ToArray());
        var before = File.ReadAllBytes(PhysicalPath("/a.txt"));

        await using (var handle = await fs.OpenAsync("/a.txt", FileOpenFlags.Read | FileOpenFlags.Write | FileOpenFlags.Create, null, Ct))
        {
            var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await handle.WriteAsync(3, "d"u8.ToArray(), Ct));
            Assert.Equal(FileSystemError.OpNotSupported, ex.Error);
        }

        Assert.Equal(before, File.ReadAllBytes(PhysicalPath("/a.txt")));
    }

    [Fact]
    public async Task Flush_writes_the_complete_chunks_and_keeps_the_last_one_until_the_close()
    {
        await using var handle = await CreateFileSystem().OpenAsync("/a.bin", WriteNew, null, Ct);
        await handle.WriteAsync(0, new byte[Chunk + 10], Ct);

        await handle.FlushAsync(Ct);

        Assert.Equal(Header + EncryptedChunk, new FileInfo(PhysicalPath("/a.bin")).Length);
        Assert.Equal(Chunk, (await CreateFileSystem().StatAsync("/a.bin", true, Ct))!.Size); // the complete chunks so far
        Assert.Equal(Chunk + 10, (await handle.StatAsync(Ct)).Size);
    }

    // ---- Helpers ----

    private EncryptedFileSystem CreateFileSystem(IMasterKeyProvider? keys = null)
        => new(new LocalFileSystem(_root), keys ?? TestKeys.Provider("a", ("a", TestKeys.KeyA)));

    private string PhysicalPath(string virtualPath) => Path.Combine(_root, virtualPath.TrimStart('/'));

    private static async Task WriteAsync(IFileSystem fs, string path, byte[] content)
    {
        await using var handle = await fs.OpenAsync(path, WriteNew, null, Ct);
        for (var offset = 0; offset < content.Length; offset += 32_768)
            await handle.WriteAsync(offset, content.AsMemory(offset, Math.Min(32_768, content.Length - offset)), Ct);
    }

    private static async Task<byte[]> ReadAsync(IFileSystem fs, string path)
    {
        await using var handle = await fs.OpenAsync(path, FileOpenFlags.Read, null, Ct);
        using var result = new MemoryStream();
        var buffer = new byte[32_768];
        int read;
        while ((read = await handle.ReadAsync(result.Length, buffer, Ct)) > 0)
            result.Write(buffer, 0, read);
        return result.ToArray();
    }

    private static async Task AssertFailureAsync(Func<Task> action)
    {
        var ex = await Assert.ThrowsAsync<FileSystemException>(action);
        Assert.Equal(FileSystemError.Failure, ex.Error);
    }
}
