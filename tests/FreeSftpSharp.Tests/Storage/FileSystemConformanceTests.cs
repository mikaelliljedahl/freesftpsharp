using System.Text;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage;

/// <summary>A new, empty storage for one conformance test. The test disposes it.</summary>
public interface IFileSystemFixture : IDisposable
{
    /// <summary>The file system under test; its root is empty.</summary>
    IFileSystem FileSystem { get; }

    /// <summary>The capabilities that the backend must declare.</summary>
    StorageCapabilities ExpectedCapabilities { get; }
}

/// <summary>
/// The contract of <see cref="IFileSystem"/> and <see cref="IFileHandle"/> (docs/ARCHITECTURE.md, "One conformance
/// suite"): one test per operation and per failure case. Every storage backend adds one subclass with its fixture and
/// passes the whole suite. A test that needs a capability checks the declared <see cref="IFileSystem.Capabilities"/>:
/// with the capability the operation works, without it the operation throws <see cref="FileSystemError.OpNotSupported"/>.
/// The tests use only the interface, so they work for every backend; checks of the physical storage are in the tests
/// of each backend.
/// </summary>
public abstract class FileSystemConformanceTests<TFixture> : IDisposable
    where TFixture : IFileSystemFixture, new()
{
    private const FileOpenFlags WriteNew = FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate;

    private readonly TFixture _fixture = new();

    protected IFileSystem Fs => _fixture.FileSystem;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private bool Has(StorageCapabilities capability) => (Fs.Capabilities & capability) == capability;

    public void Dispose() => _fixture.Dispose();

    // ---- Capabilities ----

    [Fact]
    public void Capabilities_are_the_ones_of_the_backend()
    {
        Assert.Equal(_fixture.ExpectedCapabilities, Fs.Capabilities);
    }

    // ---- StatAsync ----

    [Fact]
    public async Task Stat_of_the_root_is_a_directory()
    {
        var root = await Fs.StatAsync("/", followLinks: true, Ct);

        Assert.NotNull(root);
        Assert.Equal(FileSystemEntryType.Directory, root.Type);
        Assert.Equal("/", root.Name);
    }

    [Fact]
    public async Task Stat_of_a_file_gives_name_type_size_and_times()
    {
        var before = DateTime.UtcNow.AddMinutes(-5);
        await WriteFileAsync("/a.bin", new byte[1234]);

        var entry = await Fs.StatAsync("/a.bin", followLinks: true, Ct);

        Assert.NotNull(entry);
        Assert.Equal("a.bin", entry.Name);
        Assert.Equal(FileSystemEntryType.File, entry.Type);
        Assert.Equal(1234, entry.Size);
        Assert.InRange(entry.LastWriteTimeUtc, before, DateTime.UtcNow.AddMinutes(5));
        Assert.Equal(DateTimeKind.Utc, entry.LastWriteTimeUtc.Kind);
    }

    [Fact]
    public async Task Stat_of_a_directory_gives_directory_type()
    {
        await Fs.CreateDirectoryAsync("/dir", Ct);

        foreach (var followLinks in new[] { true, false })
        {
            var entry = await Fs.StatAsync("/dir", followLinks, Ct);
            Assert.NotNull(entry);
            Assert.Equal("dir", entry.Name);
            Assert.True(entry.IsDirectory);
            Assert.Equal(0, entry.Size);
        }
    }

    [Fact]
    public async Task Stat_of_a_missing_path_is_null()
    {
        Assert.Null(await Fs.StatAsync("/missing", followLinks: true, Ct));
        Assert.Null(await Fs.StatAsync("/missing", followLinks: false, Ct));
        Assert.Null(await Fs.StatAsync("/missing-dir/missing", followLinks: true, Ct));
    }

    [Fact]
    public async Task Stat_of_a_path_below_a_file_is_null()
    {
        await WriteFileAsync("/file.txt", "x");

        Assert.Null(await Fs.StatAsync("/file.txt/child", followLinks: true, Ct));
    }

    // ---- ListAsync ----

    [Fact]
    public async Task List_gives_the_files_and_directories_without_dot_entries()
    {
        await Fs.CreateDirectoryAsync("/dir", Ct);
        await Fs.CreateDirectoryAsync("/dir/sub", Ct);
        await WriteFileAsync("/dir/a.bin", new byte[7]);
        await WriteFileAsync("/other.txt", "not in the listing");

        var entries = await ListAsync("/dir");

        Assert.Equal(["a.bin", "sub"], entries.Select(e => e.Name).Order(StringComparer.Ordinal));
        var file = entries.Single(e => e.Name == "a.bin");
        Assert.Equal(FileSystemEntryType.File, file.Type);
        Assert.Equal(7, file.Size);
        Assert.True(entries.Single(e => e.Name == "sub").IsDirectory);
    }

    [Fact]
    public async Task List_of_the_root_and_of_an_empty_directory()
    {
        await Fs.CreateDirectoryAsync("/empty", Ct);

        Assert.Empty(await ListAsync("/empty"));
        Assert.Equal(["empty"], (await ListAsync("/")).Select(e => e.Name));
    }

    [Fact]
    public async Task List_of_a_missing_directory_throws_no_such_file()
    {
        await AssertErrorAsync(FileSystemError.NoSuchFile, () => ListAsync("/missing"));
    }

    [Fact]
    public async Task List_of_a_file_throws_not_a_directory()
    {
        await WriteFileAsync("/a.txt", "a");

        await AssertErrorAsync(FileSystemError.NotADirectory, () => ListAsync("/a.txt"));
    }

    // ---- OpenAsync, ReadAsync, WriteAsync ----

    [Fact]
    public async Task Write_and_read_a_new_file()
    {
        await using (var handle = await Fs.OpenAsync("/file.bin", FileOpenFlags.Read | WriteNew, null, Ct))
        {
            await handle.WriteAsync(0, Encoding.ASCII.GetBytes("hello"), Ct);
            await handle.WriteAsync(5, Encoding.ASCII.GetBytes(" world"), Ct);

            var buffer = new byte[100];
            var read = await handle.ReadAsync(0, buffer, Ct);
            Assert.Equal("hello world", Encoding.ASCII.GetString(buffer, 0, read));
        }

        Assert.Equal("hello world", await ReadTextAsync("/file.bin"));
    }

    [Fact]
    public async Task Read_at_and_past_the_end_of_the_file_returns_zero()
    {
        await WriteFileAsync("/a.txt", "abc");
        await using var handle = await Fs.OpenAsync("/a.txt", FileOpenFlags.Read, null, Ct);
        var buffer = new byte[10];

        Assert.Equal(0, await handle.ReadAsync(3, buffer, Ct));
        Assert.Equal(0, await handle.ReadAsync(1000, buffer, Ct));
        Assert.Equal(2, await handle.ReadAsync(1, buffer, Ct));
        Assert.Equal("bc", Encoding.ASCII.GetString(buffer, 0, 2));
    }

    [Fact]
    public async Task Read_of_an_empty_file_returns_zero()
    {
        await WriteFileAsync("/empty", []);
        await using var handle = await Fs.OpenAsync("/empty", FileOpenFlags.Read, null, Ct);

        Assert.Equal(0, await handle.ReadAsync(0, new byte[10], Ct));
    }

    [Fact]
    public async Task Write_past_the_end_extends_the_file_with_zeros_or_is_not_supported()
    {
        await using (var handle = await Fs.OpenAsync("/sparse.bin", WriteNew, null, Ct))
        {
            await handle.WriteAsync(0, new byte[] { 1 }, Ct);
            if (!Has(StorageCapabilities.RandomAccessWrite))
            {
                await AssertErrorAsync(FileSystemError.OpNotSupported, async () => await handle.WriteAsync(4, new byte[] { 2 }, Ct));
                return;
            }
            await handle.WriteAsync(4, new byte[] { 2 }, Ct);
        }

        Assert.Equal(new byte[] { 1, 0, 0, 0, 2 }, await ReadFileAsync("/sparse.bin"));
    }

    [Fact]
    public async Task Write_before_the_end_overwrites_or_is_not_supported()
    {
        await WriteFileAsync("/a.txt", "abcdef");

        await using (var handle = await Fs.OpenAsync("/a.txt", FileOpenFlags.Write, null, Ct))
        {
            if (!Has(StorageCapabilities.RandomAccessWrite))
            {
                await AssertErrorAsync(FileSystemError.OpNotSupported, async () => await handle.WriteAsync(2, Encoding.ASCII.GetBytes("XY"), Ct));
                return;
            }
            await handle.WriteAsync(2, Encoding.ASCII.GetBytes("XY"), Ct);
        }

        Assert.Equal("abXYef", await ReadTextAsync("/a.txt"));
    }

    [Fact]
    public async Task Sequential_writes_of_a_large_file_give_the_same_bytes()
    {
        var content = new byte[300_000];
        new Random(51).NextBytes(content);

        await using (var handle = await Fs.OpenAsync("/big.bin", WriteNew, null, Ct))
        {
            for (var offset = 0; offset < content.Length; offset += 32_768)
                await handle.WriteAsync(offset, content.AsMemory(offset, Math.Min(32_768, content.Length - offset)), Ct);
        }

        Assert.Equal(content, await ReadFileAsync("/big.bin"));
    }

    [Fact]
    public async Task Open_with_create_and_truncate_empties_an_existing_file()
    {
        await WriteFileAsync("/a.txt", "old content");

        await (await Fs.OpenAsync("/a.txt", WriteNew, null, Ct)).DisposeAsync();

        Assert.Equal(0, (await Fs.StatAsync("/a.txt", true, Ct))!.Size);
    }

    [Fact]
    public async Task Open_with_create_keeps_the_content_of_an_existing_file()
    {
        await WriteFileAsync("/a.txt", "keep");

        await (await Fs.OpenAsync("/a.txt", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct)).DisposeAsync();

        Assert.Equal("keep", await ReadTextAsync("/a.txt"));
    }

    [Fact]
    public async Task Open_of_a_missing_file_without_create_throws_no_such_file()
    {
        await AssertErrorAsync(FileSystemError.NoSuchFile, () => OpenAndCloseAsync("/missing.txt", FileOpenFlags.Read));
        await AssertErrorAsync(FileSystemError.NoSuchFile, () => OpenAndCloseAsync("/missing.txt", FileOpenFlags.Write));
        Assert.Null(await Fs.StatAsync("/missing.txt", true, Ct));
    }

    [Fact]
    public async Task Open_with_create_in_a_missing_directory_throws_no_such_file()
    {
        await AssertErrorAsync(FileSystemError.NoSuchFile, () => OpenAndCloseAsync("/missing-dir/new.txt", WriteNew));
        Assert.Null(await Fs.StatAsync("/missing-dir", true, Ct));
    }

    [Fact]
    public async Task Exclusive_create_of_an_existing_file_throws_already_exists_and_keeps_the_content()
    {
        await WriteFileAsync("/a.txt", "keep");

        await AssertErrorAsync(FileSystemError.AlreadyExists,
            () => OpenAndCloseAsync("/a.txt", FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Exclusive));
        Assert.Equal("keep", await ReadTextAsync("/a.txt"));
    }

    [Fact]
    public async Task Exclusive_create_of_a_new_file_works()
    {
        await OpenAndCloseAsync("/new.txt", FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Exclusive);

        Assert.NotNull(await Fs.StatAsync("/new.txt", true, Ct));
    }

    [Fact]
    public async Task Open_of_a_directory_throws_is_a_directory()
    {
        await Fs.CreateDirectoryAsync("/dir", Ct);

        await AssertErrorAsync(FileSystemError.IsADirectory, () => OpenAndCloseAsync("/dir", FileOpenFlags.Read));
        await AssertErrorAsync(FileSystemError.IsADirectory, () => OpenAndCloseAsync("/dir", WriteNew));
        await AssertErrorAsync(FileSystemError.IsADirectory, () => OpenAndCloseAsync("/", FileOpenFlags.Read));
        Assert.True((await Fs.StatAsync("/dir", true, Ct))!.IsDirectory);
    }

    [Fact]
    public async Task Append_writes_at_the_end_whatever_the_offset_or_is_not_supported()
    {
        await WriteFileAsync("/a.txt", "abc");

        if (!Has(StorageCapabilities.Append))
        {
            await AssertErrorAsync(FileSystemError.OpNotSupported, () => OpenAndCloseAsync("/a.txt", FileOpenFlags.Write | FileOpenFlags.Append));
            Assert.Equal("abc", await ReadTextAsync("/a.txt"));
            return;
        }

        await using (var handle = await Fs.OpenAsync("/a.txt", FileOpenFlags.Write | FileOpenFlags.Append, null, Ct))
        {
            await handle.WriteAsync(0, Encoding.ASCII.GetBytes("def"), Ct);
            await handle.WriteAsync(1, Encoding.ASCII.GetBytes("g"), Ct);
        }

        Assert.Equal("abcdefg", await ReadTextAsync("/a.txt"));
    }

    [Fact]
    public async Task Read_of_a_handle_without_read_access_throws_permission_denied()
    {
        await using var handle = await Fs.OpenAsync("/a.txt", WriteNew, null, Ct);

        await AssertErrorAsync(FileSystemError.PermissionDenied, async () => await handle.ReadAsync(0, new byte[1], Ct));
    }

    [Fact]
    public async Task Write_of_a_handle_without_write_access_throws_permission_denied()
    {
        await WriteFileAsync("/a.txt", "a");
        await using var handle = await Fs.OpenAsync("/a.txt", FileOpenFlags.Read, null, Ct);

        await AssertErrorAsync(FileSystemError.PermissionDenied, async () => await handle.WriteAsync(1, new byte[1], Ct));
        Assert.Equal("a", await ReadTextAsync("/a.txt"));
    }

    [Fact]
    public async Task Open_applies_the_initial_permissions_only_to_a_new_file()
    {
        if (!Has(StorageCapabilities.SetPermissions))
        {
            await OpenAndCloseAsync("/new.txt", WriteNew, new FileAttributesUpdate { Permissions = 0x124 });
            Assert.NotNull(await Fs.StatAsync("/new.txt", true, Ct));
            return;
        }

        await WriteFileAsync("/existing.txt", "a");
        var before = (await Fs.StatAsync("/existing.txt", true, Ct))!.Permissions;

        await OpenAndCloseAsync("/new.txt", WriteNew, new FileAttributesUpdate { Permissions = 0x124 }); // r--r--r--
        await OpenAndCloseAsync("/existing.txt", WriteNew, new FileAttributesUpdate { Permissions = 0x124 });

        Assert.Equal(0x124u, (await Fs.StatAsync("/new.txt", true, Ct))!.Permissions);
        Assert.Equal(before, (await Fs.StatAsync("/existing.txt", true, Ct))!.Permissions);
    }

    [Fact]
    public async Task Two_handles_of_the_same_file_can_be_open()
    {
        await WriteFileAsync("/a.txt", "shared");

        await using var first = await Fs.OpenAsync("/a.txt", FileOpenFlags.Read, null, Ct);
        await using var second = await Fs.OpenAsync("/a.txt", FileOpenFlags.Read, null, Ct);

        Assert.Equal(6, await first.ReadAsync(0, new byte[10], Ct));
        Assert.Equal(6, await second.ReadAsync(0, new byte[10], Ct));
    }

    // ---- IFileHandle: FlushAsync, StatAsync, SetAttributesAsync, DisposeAsync ----

    [Fact]
    public async Task Flush_of_a_written_file_succeeds_and_the_data_is_kept()
    {
        await using (var handle = await Fs.OpenAsync("/a.txt", WriteNew, null, Ct))
        {
            await handle.WriteAsync(0, Encoding.ASCII.GetBytes("durable"), Ct);
            await handle.FlushAsync(Ct);
        }

        Assert.Equal("durable", await ReadTextAsync("/a.txt"));
    }

    [Fact]
    public async Task Handle_stat_gives_the_size_of_the_written_data_before_close()
    {
        await using var handle = await Fs.OpenAsync("/a.bin", WriteNew, null, Ct);
        await handle.WriteAsync(0, new byte[300], Ct);

        var entry = await handle.StatAsync(Ct);

        Assert.Equal(FileSystemEntryType.File, entry.Type);
        Assert.Equal(300, entry.Size);
    }

    [Fact]
    public async Task Handle_set_attributes_changes_the_size_of_the_open_file_or_is_not_supported()
    {
        await using (var handle = await Fs.OpenAsync("/a.txt", WriteNew, null, Ct))
        {
            await handle.WriteAsync(0, Encoding.ASCII.GetBytes("abcdef"), Ct);
            var update = new FileAttributesUpdate { Size = 3 };
            if (!Has(StorageCapabilities.RandomAccessWrite))
            {
                await AssertErrorAsync(FileSystemError.OpNotSupported, async () => await handle.SetAttributesAsync(update, Ct));
                return;
            }
            await handle.SetAttributesAsync(update, Ct);
            Assert.Equal(3, (await handle.StatAsync(Ct)).Size);
        }

        Assert.Equal("abc", await ReadTextAsync("/a.txt"));
    }

    [Fact]
    public async Task Handle_set_attributes_times_stay_after_close_or_are_not_supported()
    {
        var mtime = new DateTime(2024, 5, 6, 7, 8, 9, DateTimeKind.Utc);
        await using (var handle = await Fs.OpenAsync("/a.txt", WriteNew, null, Ct))
        {
            await handle.WriteAsync(0, Encoding.ASCII.GetBytes("data"), Ct);
            var update = new FileAttributesUpdate { LastWriteTimeUtc = mtime };
            if (!Has(StorageCapabilities.SetTimes))
            {
                await AssertErrorAsync(FileSystemError.OpNotSupported, async () => await handle.SetAttributesAsync(update, Ct));
                return;
            }
            await handle.SetAttributesAsync(update, Ct);
        }

        Assert.Equal(mtime, (await Fs.StatAsync("/a.txt", true, Ct))!.LastWriteTimeUtc);
    }

    [Fact]
    public async Task Dispose_twice_does_nothing()
    {
        var handle = await Fs.OpenAsync("/a.txt", WriteNew, null, Ct);

        await handle.DisposeAsync();
        await handle.DisposeAsync();
    }

    // ---- CreateDirectoryAsync ----

    [Fact]
    public async Task Create_directory_creates_it()
    {
        await Fs.CreateDirectoryAsync("/new", Ct);
        await Fs.CreateDirectoryAsync("/new/sub", Ct);

        Assert.True((await Fs.StatAsync("/new/sub", true, Ct))!.IsDirectory);
    }

    [Fact]
    public async Task Create_directory_of_an_existing_path_throws_already_exists()
    {
        await Fs.CreateDirectoryAsync("/dir", Ct);
        await WriteFileAsync("/a.txt", "a");

        await AssertErrorAsync(FileSystemError.AlreadyExists, () => Fs.CreateDirectoryAsync("/dir", Ct).AsTask());
        await AssertErrorAsync(FileSystemError.AlreadyExists, () => Fs.CreateDirectoryAsync("/a.txt", Ct).AsTask());
        await AssertErrorAsync(FileSystemError.AlreadyExists, () => Fs.CreateDirectoryAsync("/", Ct).AsTask());
        Assert.Equal("a", await ReadTextAsync("/a.txt"));
    }

    [Fact]
    public async Task Create_directory_without_the_parent_throws_no_such_file()
    {
        await AssertErrorAsync(FileSystemError.NoSuchFile, () => Fs.CreateDirectoryAsync("/missing/new", Ct).AsTask());
        Assert.Null(await Fs.StatAsync("/missing", true, Ct));
    }

    // ---- DeleteFileAsync ----

    [Fact]
    public async Task Delete_file_removes_it()
    {
        await WriteFileAsync("/a.txt", "a");

        await Fs.DeleteFileAsync("/a.txt", Ct);

        Assert.Null(await Fs.StatAsync("/a.txt", true, Ct));
    }

    [Fact]
    public async Task Delete_file_of_a_missing_path_throws_no_such_file()
    {
        await AssertErrorAsync(FileSystemError.NoSuchFile, () => Fs.DeleteFileAsync("/missing.txt", Ct).AsTask());
        await AssertErrorAsync(FileSystemError.NoSuchFile, () => Fs.DeleteFileAsync("/missing-dir/missing.txt", Ct).AsTask());
    }

    [Fact]
    public async Task Delete_file_of_a_directory_throws_is_a_directory_and_keeps_it()
    {
        await Fs.CreateDirectoryAsync("/dir", Ct);

        await AssertErrorAsync(FileSystemError.IsADirectory, () => Fs.DeleteFileAsync("/dir", Ct).AsTask());
        Assert.NotNull(await Fs.StatAsync("/dir", true, Ct));
    }

    // ---- DeleteDirectoryAsync ----

    [Fact]
    public async Task Delete_directory_removes_an_empty_directory()
    {
        await Fs.CreateDirectoryAsync("/dir", Ct);

        await Fs.DeleteDirectoryAsync("/dir", Ct);

        Assert.Null(await Fs.StatAsync("/dir", true, Ct));
    }

    [Fact]
    public async Task Delete_directory_that_is_not_empty_throws_directory_not_empty()
    {
        await Fs.CreateDirectoryAsync("/dir", Ct);
        await WriteFileAsync("/dir/a.txt", "a");

        await AssertErrorAsync(FileSystemError.DirectoryNotEmpty, () => Fs.DeleteDirectoryAsync("/dir", Ct).AsTask());
        Assert.Equal("a", await ReadTextAsync("/dir/a.txt"));
    }

    [Fact]
    public async Task Delete_directory_of_a_missing_path_throws_no_such_file()
    {
        await AssertErrorAsync(FileSystemError.NoSuchFile, () => Fs.DeleteDirectoryAsync("/missing", Ct).AsTask());
    }

    [Fact]
    public async Task Delete_directory_of_a_file_throws_not_a_directory_and_keeps_the_file()
    {
        await WriteFileAsync("/a.txt", "a");

        await AssertErrorAsync(FileSystemError.NotADirectory, () => Fs.DeleteDirectoryAsync("/a.txt", Ct).AsTask());
        Assert.Equal("a", await ReadTextAsync("/a.txt"));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("")]
    [InlineData("/..")]
    [InlineData("/../..")]
    public async Task Delete_directory_of_the_root_throws_permission_denied(string path)
    {
        await AssertErrorAsync(FileSystemError.PermissionDenied, () => Fs.DeleteDirectoryAsync(path, Ct).AsTask());
        Assert.NotNull(await Fs.StatAsync("/", true, Ct));
    }

    // ---- RenameAsync ----

    [Fact]
    public async Task Rename_moves_a_file_and_a_directory_with_its_content()
    {
        await WriteFileAsync("/old.txt", "x");
        await Fs.CreateDirectoryAsync("/olddir", Ct);
        await WriteFileAsync("/olddir/inner.txt", "i");

        if (!Has(StorageCapabilities.Rename))
        {
            await AssertErrorAsync(FileSystemError.OpNotSupported, () => RenameAsync("/old.txt", "/new.txt", RenameFlags.None));
            Assert.Equal("x", await ReadTextAsync("/old.txt"));
            return;
        }
        await RenameAsync("/old.txt", "/new.txt", RenameFlags.None);
        await RenameAsync("/olddir", "/newdir", RenameFlags.None);

        Assert.Equal("x", await ReadTextAsync("/new.txt"));
        Assert.Null(await Fs.StatAsync("/old.txt", true, Ct));
        Assert.Equal("i", await ReadTextAsync("/newdir/inner.txt"));
        Assert.Null(await Fs.StatAsync("/olddir", true, Ct));
    }

    [Fact]
    public async Task Rename_of_a_missing_path_throws_no_such_file()
    {
        await AssertRenameErrorAsync(FileSystemError.NoSuchFile, "/missing.txt", "/new.txt", RenameFlags.None);
        await AssertRenameErrorAsync(FileSystemError.NoSuchFile, "/missing.txt", "/new.txt", RenameFlags.ReplaceExisting);
    }

    [Fact]
    public async Task Rename_into_a_missing_directory_throws_no_such_file()
    {
        await WriteFileAsync("/a.txt", "a");

        await AssertRenameErrorAsync(FileSystemError.NoSuchFile, "/a.txt", "/missing/a.txt", RenameFlags.None);
        Assert.Equal("a", await ReadTextAsync("/a.txt"));
    }

    [Fact]
    public async Task Rename_over_an_existing_file_throws_already_exists_and_changes_nothing()
    {
        await WriteFileAsync("/a.txt", "a");
        await WriteFileAsync("/b.txt", "b");

        await AssertRenameErrorAsync(FileSystemError.AlreadyExists, "/a.txt", "/b.txt", RenameFlags.None);

        Assert.Equal("a", await ReadTextAsync("/a.txt"));
        Assert.Equal("b", await ReadTextAsync("/b.txt"));
    }

    [Fact]
    public async Task Rename_replacing_an_existing_file_replaces_it()
    {
        await WriteFileAsync("/new.txt", "new content");
        await WriteFileAsync("/old.txt", "old content");

        if (!Has(StorageCapabilities.Rename))
        {
            await AssertErrorAsync(FileSystemError.OpNotSupported, () => RenameAsync("/new.txt", "/old.txt", RenameFlags.ReplaceExisting));
            return;
        }
        await RenameAsync("/new.txt", "/old.txt", RenameFlags.ReplaceExisting);

        Assert.Null(await Fs.StatAsync("/new.txt", true, Ct));
        Assert.Equal("new content", await ReadTextAsync("/old.txt"));
    }

    [Fact]
    public async Task Rename_replacing_of_a_file_onto_a_directory_throws_is_a_directory()
    {
        await WriteFileAsync("/a.txt", "a");
        await Fs.CreateDirectoryAsync("/dir", Ct);

        await AssertRenameErrorAsync(FileSystemError.IsADirectory, "/a.txt", "/dir", RenameFlags.ReplaceExisting);

        Assert.Equal("a", await ReadTextAsync("/a.txt"));
        Assert.True((await Fs.StatAsync("/dir", true, Ct))!.IsDirectory);
    }

    [Fact]
    public async Task Rename_replacing_of_a_directory_onto_an_existing_path_throws_already_exists()
    {
        await Fs.CreateDirectoryAsync("/dir", Ct);
        await Fs.CreateDirectoryAsync("/other", Ct);
        await WriteFileAsync("/a.txt", "a");

        await AssertRenameErrorAsync(FileSystemError.AlreadyExists, "/dir", "/a.txt", RenameFlags.ReplaceExisting);
        await AssertRenameErrorAsync(FileSystemError.AlreadyExists, "/dir", "/other", RenameFlags.ReplaceExisting);

        Assert.True((await Fs.StatAsync("/dir", true, Ct))!.IsDirectory);
        Assert.Equal("a", await ReadTextAsync("/a.txt"));
    }

    [Theory]
    [InlineData("/", RenameFlags.None)]
    [InlineData("/..", RenameFlags.None)]
    [InlineData("/", RenameFlags.ReplaceExisting)]
    public async Task Rename_of_the_root_throws_permission_denied(string root, RenameFlags flags)
    {
        await AssertRenameErrorAsync(FileSystemError.PermissionDenied, root, "/moved", flags);
        Assert.NotNull(await Fs.StatAsync("/", true, Ct));
        Assert.Null(await Fs.StatAsync("/moved", true, Ct));
    }

    [Fact]
    public async Task Rename_onto_the_root_throws_permission_denied()
    {
        await WriteFileAsync("/a.txt", "a");

        await AssertRenameErrorAsync(FileSystemError.PermissionDenied, "/a.txt", "/", RenameFlags.ReplaceExisting);
        Assert.Equal("a", await ReadTextAsync("/a.txt"));
    }

    [Fact]
    public async Task Open_handle_keeps_working_after_its_file_is_renamed()
    {
        if (!Has(StorageCapabilities.Rename))
            return; // nothing to rename; Rename_moves_a_file_and_a_directory_with_its_content checks OpNotSupported

        await WriteFileAsync("/a.txt", "abc");
        await using var handle = await Fs.OpenAsync("/a.txt", FileOpenFlags.Read, null, Ct);

        await RenameAsync("/a.txt", "/b.txt", RenameFlags.None);

        var buffer = new byte[10];
        Assert.Equal(3, await handle.ReadAsync(0, buffer, Ct));
    }

    // ---- SetAttributesAsync ----

    [Fact]
    public async Task Set_attributes_size_truncates_and_extends_or_is_not_supported()
    {
        await WriteFileAsync("/a.txt", "abcdef");

        if (!Has(StorageCapabilities.RandomAccessWrite))
        {
            await AssertErrorAsync(FileSystemError.OpNotSupported, () => Fs.SetAttributesAsync("/a.txt", new FileAttributesUpdate { Size = 2 }, Ct).AsTask());
            Assert.Equal("abcdef", await ReadTextAsync("/a.txt"));
            return;
        }
        await Fs.SetAttributesAsync("/a.txt", new FileAttributesUpdate { Size = 2 }, Ct);
        Assert.Equal("ab", await ReadTextAsync("/a.txt"));

        await Fs.SetAttributesAsync("/a.txt", new FileAttributesUpdate { Size = 5 }, Ct);
        Assert.Equal(new byte[] { (byte)'a', (byte)'b', 0, 0, 0 }, await ReadFileAsync("/a.txt"));
    }

    [Fact]
    public async Task Set_attributes_times_of_a_file_and_a_directory_or_is_not_supported()
    {
        var atime = DateTimeOffset.FromUnixTimeSeconds(1_600_000_000).UtcDateTime;
        var mtime = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000).UtcDateTime;
        var update = new FileAttributesUpdate { LastAccessTimeUtc = atime, LastWriteTimeUtc = mtime };
        await WriteFileAsync("/a.txt", "a");
        await Fs.CreateDirectoryAsync("/dir", Ct);

        if (!Has(StorageCapabilities.SetTimes))
        {
            await AssertErrorAsync(FileSystemError.OpNotSupported, () => Fs.SetAttributesAsync("/a.txt", update, Ct).AsTask());
            return;
        }

        await Fs.SetAttributesAsync("/a.txt", update, Ct);
        await Fs.SetAttributesAsync("/dir", update, Ct);

        var file = (await Fs.StatAsync("/a.txt", true, Ct))!;
        Assert.Equal(mtime, file.LastWriteTimeUtc);
        Assert.Equal(atime, file.LastAccessTimeUtc);
        Assert.Equal(mtime, (await Fs.StatAsync("/dir", true, Ct))!.LastWriteTimeUtc);
    }

    [Fact]
    public async Task Set_attributes_with_only_one_time_keeps_the_other()
    {
        if (!Has(StorageCapabilities.SetTimes))
            return; // Set_attributes_times_of_a_file_and_a_directory_or_is_not_supported checks OpNotSupported

        var atime = DateTimeOffset.FromUnixTimeSeconds(1_600_000_000).UtcDateTime;
        var mtime = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000).UtcDateTime;
        await WriteFileAsync("/a.txt", "a");
        await Fs.SetAttributesAsync("/a.txt", new FileAttributesUpdate { LastAccessTimeUtc = atime, LastWriteTimeUtc = mtime }, Ct);

        await Fs.SetAttributesAsync("/a.txt", new FileAttributesUpdate { LastWriteTimeUtc = mtime.AddDays(1) }, Ct);

        var file = (await Fs.StatAsync("/a.txt", true, Ct))!;
        Assert.Equal(mtime.AddDays(1), file.LastWriteTimeUtc);
        Assert.Equal(atime, file.LastAccessTimeUtc);
    }

    [Theory]
    [InlineData(0x124u)] // r--r--r--: on Windows a read-only file
    [InlineData(0x1A4u)] // rw-r--r--
    public async Task Set_attributes_permissions_or_is_not_supported(uint permissions)
    {
        await WriteFileAsync("/a.txt", "a");
        var update = new FileAttributesUpdate { Permissions = 0x8000 | permissions };
        if (!Has(StorageCapabilities.SetPermissions))
        {
            await AssertErrorAsync(FileSystemError.OpNotSupported, () => Fs.SetAttributesAsync("/a.txt", update, Ct).AsTask());
            return;
        }

        await Fs.SetAttributesAsync("/a.txt", update, Ct);

        Assert.Equal(permissions, (await Fs.StatAsync("/a.txt", true, Ct))!.Permissions);
        await Fs.SetAttributesAsync("/a.txt", new FileAttributesUpdate { Permissions = 0x1A4 }, Ct); // writable, so the fixture can remove it
    }

    [Fact]
    public async Task Set_attributes_permissions_of_the_root_throws_permission_denied()
    {
        var expected = Has(StorageCapabilities.SetPermissions) ? FileSystemError.PermissionDenied : FileSystemError.OpNotSupported;

        await AssertErrorAsync(expected, () => Fs.SetAttributesAsync("/", new FileAttributesUpdate { Permissions = 0 }, Ct).AsTask());
        await AssertErrorAsync(expected, () => Fs.SetAttributesAsync("/..", new FileAttributesUpdate { Permissions = 0 }, Ct).AsTask());
    }

    [Fact]
    public async Task Set_attributes_of_a_missing_path_throws_no_such_file()
    {
        await AssertErrorAsync(FileSystemError.NoSuchFile, () => Fs.SetAttributesAsync("/missing", new FileAttributesUpdate(), Ct).AsTask());
        Assert.Null(await Fs.StatAsync("/missing", true, Ct));
    }

    // ---- GetStorageSpaceAsync ----

    [Fact]
    public async Task Storage_space_of_the_root_is_consistent_or_unknown()
    {
        var space = await Fs.GetStorageSpaceAsync("/", Ct);

        if (space != null)
        {
            Assert.True(space.TotalBytes > 0);
            Assert.InRange(space.FreeBytes, 0ul, space.TotalBytes);
            Assert.InRange(space.AvailableBytes, 0ul, space.TotalBytes);
        }
    }

    [Fact]
    public async Task Storage_space_of_a_missing_path_throws_no_such_file()
    {
        await AssertErrorAsync(FileSystemError.NoSuchFile, () => Fs.GetStorageSpaceAsync("/missing", Ct).AsTask());
    }

    // ---- Paths ----

    [Theory]
    [InlineData("/../a.txt")]
    [InlineData("/../../a.txt")]
    [InlineData("../a.txt")]
    [InlineData("..\\..\\a.txt")]
    [InlineData("/x/../../a.txt")]
    [InlineData("//a.txt")]
    [InlineData("/./a.txt")]
    [InlineData("a.txt")]
    public async Task Path_traversal_stays_inside_the_root(string path)
    {
        await WriteFileAsync(path, "inside");

        Assert.Equal("inside", await ReadTextAsync("/a.txt"));
        Assert.Equal(["a.txt"], (await ListAsync("/..")).Select(e => e.Name));
        Assert.Equal("a.txt", (await Fs.StatAsync(path, true, Ct))!.Name);
    }

    [Fact]
    public async Task Backslash_is_a_separator()
    {
        await Fs.CreateDirectoryAsync("/dir", Ct);
        await WriteFileAsync("\\dir\\a.txt", "a");

        Assert.Equal("a", await ReadTextAsync("/dir/a.txt"));
    }

    [Fact]
    public async Task Names_with_spaces_and_unicode_work()
    {
        await Fs.CreateDirectoryAsync("/my dir", Ct);
        await WriteFileAsync("/my dir/räksmörgås ✓.txt", "x");

        Assert.Equal(["räksmörgås ✓.txt"], (await ListAsync("/my dir")).Select(e => e.Name));
        Assert.Equal("x", await ReadTextAsync("/my dir/räksmörgås ✓.txt"));
    }

    // ---- Cancellation ----

    [Fact]
    public async Task A_canceled_token_throws_operation_canceled()
    {
        using var canceled = new CancellationTokenSource();
        await canceled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await Fs.StatAsync("/", true, canceled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await Fs.CreateDirectoryAsync("/dir", canceled.Token));
        Assert.Null(await Fs.StatAsync("/dir", true, Ct));
    }

    // ---- Helpers ----

    private async Task WriteFileAsync(string path, string content) => await WriteFileAsync(path, Encoding.UTF8.GetBytes(content));

    private async Task WriteFileAsync(string path, byte[] content)
    {
        await using var handle = await Fs.OpenAsync(path, WriteNew, null, Ct);
        if (content.Length > 0)
            await handle.WriteAsync(0, content, Ct);
    }

    private async Task<byte[]> ReadFileAsync(string path)
    {
        await using var handle = await Fs.OpenAsync(path, FileOpenFlags.Read, null, Ct);
        using var result = new MemoryStream();
        var buffer = new byte[65_536];
        int read;
        while ((read = await handle.ReadAsync(result.Length, buffer, Ct)) > 0)
            result.Write(buffer, 0, read);
        return result.ToArray();
    }

    private async Task<string> ReadTextAsync(string path) => Encoding.UTF8.GetString(await ReadFileAsync(path));

    private async Task<List<FileSystemEntry>> ListAsync(string path)
    {
        var entries = new List<FileSystemEntry>();
        await foreach (var entry in Fs.ListAsync(path, Ct))
            entries.Add(entry);
        return entries;
    }

    private async Task OpenAndCloseAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial = null)
        => await (await Fs.OpenAsync(path, flags, initial, Ct)).DisposeAsync();

    private Task RenameAsync(string oldPath, string newPath, RenameFlags flags) => Fs.RenameAsync(oldPath, newPath, flags, Ct).AsTask();

    /// <summary>
    /// The rename fails with <paramref name="expected"/>; a backend without <see cref="StorageCapabilities.Rename"/>
    /// fails with <see cref="FileSystemError.OpNotSupported"/> instead.
    /// </summary>
    private Task AssertRenameErrorAsync(FileSystemError expected, string oldPath, string newPath, RenameFlags flags)
        => AssertErrorAsync(Has(StorageCapabilities.Rename) ? expected : FileSystemError.OpNotSupported, () => RenameAsync(oldPath, newPath, flags));

    private static async Task AssertErrorAsync(FileSystemError expected, Func<Task> action)
    {
        var ex = await Assert.ThrowsAsync<FileSystemException>(action);
        Assert.Equal(expected, ex.Error);
    }
}
