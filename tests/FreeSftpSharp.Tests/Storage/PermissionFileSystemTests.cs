using System.Text;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Storage;

/// <summary>
/// <see cref="PermissionFileSystem"/> over <see cref="InMemoryFileSystem"/> (issue #59): each permission allows its own
/// operations only, the most specific directory wins, and the path filters deny or hide names.
/// </summary>
public sealed class PermissionFileSystemTests
{
    private const FileOpenFlags WriteNew = FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly InMemoryFileSystem _backend = new();

    private async Task SeedAsync()
    {
        await _backend.CreateDirectoryAsync("/incoming", Ct);
        await _backend.CreateDirectoryAsync("/incoming/sub", Ct);
        await _backend.CreateDirectoryAsync("/outgoing", Ct);
        await WriteAsync(_backend, "/incoming/old.txt", "old");
        await WriteAsync(_backend, "/outgoing/report.txt", "report");
    }

    private PermissionFileSystem Create(Dictionary<string, FilePermissions> permissions, Dictionary<string, PathFilter>? filters = null, IFileSystem? inner = null)
        => new(inner ?? _backend, new EffectivePermissions(permissions, filters ?? new Dictionary<string, PathFilter>()));

    /// <summary>The example of the issue: "/" can list, "/incoming" can only upload, "/incoming/sub" can do everything.</summary>
    private PermissionFileSystem Incoming() => Create(new()
    {
        ["/"] = FilePermissions.List,
        ["/incoming"] = FilePermissions.Upload,
        ["/incoming/sub"] = FilePermissions.All,
    });

    [Fact]
    public async Task Upload_only_can_create_a_new_file()
    {
        await SeedAsync();
        var fs = Incoming();

        await WriteAsync(fs, "/incoming/new.txt", "new");

        Assert.Equal("new", await ReadAsync(_backend, "/incoming/new.txt"));
    }

    [Fact]
    public async Task Upload_only_cannot_list_download_overwrite_delete_rename_or_stat()
    {
        await SeedAsync();
        var fs = Incoming();

        await AssertDeniedAsync(() => ListAsync(fs, "/incoming"));
        await AssertDeniedAsync(() => ReadAsync(fs, "/incoming/old.txt"));
        await AssertDeniedAsync(() => WriteAsync(fs, "/incoming/old.txt", "overwritten"));
        await AssertDeniedAsync(() => fs.OpenAsync("/incoming/old.txt", FileOpenFlags.Write | FileOpenFlags.Append, null, Ct).AsTask());
        await AssertDeniedAsync(() => fs.DeleteFileAsync("/incoming/old.txt", Ct).AsTask());
        await AssertDeniedAsync(() => fs.RenameAsync("/incoming/old.txt", "/incoming/other.txt", RenameFlags.None, Ct).AsTask());
        await AssertDeniedAsync(() => fs.StatAsync("/incoming/old.txt", true, Ct).AsTask());
        await AssertDeniedAsync(() => fs.CreateDirectoryAsync("/incoming/dir", Ct).AsTask());
        await AssertDeniedAsync(() => fs.SetAttributesAsync("/incoming/old.txt", new FileAttributesUpdate { Size = 0 }, Ct).AsTask());
        Assert.Equal("old", await ReadAsync(_backend, "/incoming/old.txt"));
    }

    [Fact]
    public async Task The_directory_itself_is_visible_with_the_permissions_of_its_parent()
    {
        await SeedAsync();
        var fs = Incoming();

        Assert.True((await fs.StatAsync("/incoming", true, Ct))!.IsDirectory);
        Assert.Contains("incoming", (await ListAsync(fs, "/")).Select(e => e.Name));
    }

    [Fact]
    public async Task A_more_specific_directory_overrides_the_permissions_of_its_parent()
    {
        await SeedAsync();
        var fs = Incoming();

        await WriteAsync(fs, "/incoming/sub/a.txt", "a");
        await WriteAsync(fs, "/incoming/sub/a.txt", "b");
        Assert.Equal("b", await ReadAsync(fs, "/incoming/sub/a.txt"));
        Assert.Equal(["a.txt"], (await ListAsync(fs, "/incoming/sub")).Select(e => e.Name));
        await fs.RenameAsync("/incoming/sub/a.txt", "/incoming/sub/b.txt", RenameFlags.None, Ct);
        await fs.DeleteFileAsync("/incoming/sub/b.txt", Ct);
        Assert.Empty(await ListAsync(fs, "/incoming/sub"));
    }

    [Fact]
    public async Task Overwrite_without_upload_can_write_an_existing_file_but_not_create_one()
    {
        await SeedAsync();
        var fs = Create(new() { ["/"] = FilePermissions.Overwrite });

        await WriteAsync(fs, "/incoming/old.txt", "changed");
        await AssertDeniedAsync(() => WriteAsync(fs, "/incoming/new.txt", "new"));

        Assert.Equal("changed", await ReadAsync(_backend, "/incoming/old.txt"));
        Assert.Null(await _backend.StatAsync("/incoming/new.txt", true, Ct));
    }

    [Fact]
    public async Task Upload_without_overwrite_opens_the_new_file_exclusively_so_a_file_that_appears_meanwhile_is_not_overwritten()
    {
        await SeedAsync();
        var racing = new FileAppearsOnOpen(_backend, "/incoming/race.txt");
        var fs = Create(new() { ["/"] = FilePermissions.Upload }, inner: racing);

        var ex = await Assert.ThrowsAsync<FileSystemException>(() => WriteAsync(fs, "/incoming/race.txt", "mine"));

        Assert.Equal(FileSystemError.AlreadyExists, ex.Error);
        Assert.Equal("theirs", await ReadAsync(_backend, "/incoming/race.txt"));
    }

    [Fact]
    public async Task Download_only_can_read_and_not_write()
    {
        await SeedAsync();
        var fs = Create(new() { ["/"] = FilePermissions.Download });

        Assert.Equal("report", await ReadAsync(fs, "/outgoing/report.txt"));
        await AssertDeniedAsync(() => fs.OpenAsync("/outgoing/report.txt", FileOpenFlags.Read | FileOpenFlags.Write, null, Ct).AsTask());
        await AssertDeniedAsync(() => fs.DeleteFileAsync("/outgoing/report.txt", Ct).AsTask());
    }

    [Fact]
    public async Task The_attributes_need_their_own_permission_also_through_a_handle()
    {
        await SeedAsync();
        var fs = Create(new() { ["/"] = FilePermissions.All & ~(FilePermissions.ChangeMode | FilePermissions.ChangeTimes) });

        await AssertDeniedAsync(() => fs.SetAttributesAsync("/outgoing/report.txt", new FileAttributesUpdate { Permissions = 0x180 }, Ct).AsTask());
        await AssertDeniedAsync(() => fs.SetAttributesAsync("/outgoing/report.txt", new FileAttributesUpdate { LastWriteTimeUtc = DateTime.UtcNow }, Ct).AsTask());
        await fs.SetAttributesAsync("/outgoing/report.txt", new FileAttributesUpdate { Size = 2 }, Ct);

        await using var handle = await fs.OpenAsync("/outgoing/report.txt", FileOpenFlags.Write, null, Ct);
        await AssertDeniedAsync(() => handle.SetAttributesAsync(new FileAttributesUpdate { Permissions = 0x180 }, Ct).AsTask());
        await handle.SetAttributesAsync(new FileAttributesUpdate { Size = 1 }, Ct);
        Assert.Equal(1, (await handle.StatAsync(Ct)).Size);
    }

    [Fact]
    public async Task A_handle_cannot_truncate_without_overwrite()
    {
        await SeedAsync();
        var fs = Create(new() { ["/"] = FilePermissions.Upload | FilePermissions.Download });

        await using var handle = await fs.OpenAsync("/outgoing/report.txt", FileOpenFlags.Read, null, Ct);

        await AssertDeniedAsync(() => handle.SetAttributesAsync(new FileAttributesUpdate { Size = 0 }, Ct).AsTask());
    }

    [Fact]
    public async Task Rename_needs_the_permission_in_the_source_and_in_the_target_directory()
    {
        await SeedAsync();
        var fs = Create(new() { ["/"] = FilePermissions.All, ["/outgoing"] = FilePermissions.List | FilePermissions.Download });

        await AssertDeniedAsync(() => fs.RenameAsync("/incoming/old.txt", "/outgoing/old.txt", RenameFlags.None, Ct).AsTask());
        await AssertDeniedAsync(() => fs.RenameAsync("/outgoing/report.txt", "/report.txt", RenameFlags.None, Ct).AsTask());
        await fs.RenameAsync("/incoming/old.txt", "/old.txt", RenameFlags.None, Ct);
        Assert.NotNull(await _backend.StatAsync("/old.txt", true, Ct));
    }

    [Fact]
    public async Task Rename_onto_an_existing_file_needs_overwrite_in_the_target_directory()
    {
        await SeedAsync();
        await WriteAsync(_backend, "/incoming/sub/target.txt", "target");
        var fs = Create(new() { ["/"] = FilePermissions.All & ~FilePermissions.Overwrite });

        var ex = await Assert.ThrowsAsync<FileSystemException>(() =>
            fs.RenameAsync("/incoming/old.txt", "/incoming/sub/target.txt", RenameFlags.ReplaceExisting, Ct).AsTask());

        Assert.Equal(FileSystemError.AlreadyExists, ex.Error); // ReplaceExisting is dropped: the target stays
        Assert.Equal("target", await ReadAsync(_backend, "/incoming/sub/target.txt"));
        await fs.RenameAsync("/incoming/old.txt", "/incoming/sub/new.txt", RenameFlags.ReplaceExisting, Ct);
    }

    [Fact]
    public async Task A_directory_with_own_rules_cannot_be_renamed_and_nothing_can_be_renamed_onto_it()
    {
        await SeedAsync();
        var fs = Incoming();
        var all = Create(new() { ["/"] = FilePermissions.All, ["/incoming/sub"] = FilePermissions.Download });

        // Moving "/incoming" away would take its files out of its rules; moving a directory there would give it the rules.
        await AssertDeniedAsync(() => all.RenameAsync("/incoming", "/elsewhere", RenameFlags.None, Ct).AsTask());
        await AssertDeniedAsync(() => all.RenameAsync("/incoming/sub", "/sub", RenameFlags.None, Ct).AsTask());
        await AssertDeniedAsync(() => all.RenameAsync("/outgoing", "/incoming/sub", RenameFlags.None, Ct).AsTask());
        await all.RenameAsync("/outgoing", "/outgoing2", RenameFlags.None, Ct);
        await AssertDeniedAsync(() => fs.RenameAsync("/incoming/sub", "/incoming/sub2", RenameFlags.None, Ct).AsTask());
    }

    [Fact]
    public async Task Create_directory_and_delete_need_their_permission_in_the_parent()
    {
        await SeedAsync();
        var fs = Create(new() { ["/"] = FilePermissions.CreateDirectories, ["/outgoing"] = FilePermissions.Delete });

        await fs.CreateDirectoryAsync("/new", Ct);
        await AssertDeniedAsync(() => fs.DeleteDirectoryAsync("/new", Ct).AsTask());
        await fs.DeleteFileAsync("/outgoing/report.txt", Ct);
        await AssertDeniedAsync(() => fs.CreateDirectoryAsync("/outgoing/dir", Ct).AsTask());
    }

    [Fact]
    public async Task Paths_are_normalized_before_the_rules_are_found()
    {
        await SeedAsync();
        var fs = Incoming();

        await AssertDeniedAsync(() => ReadAsync(fs, "/incoming/sub/../old.txt"));
        await AssertDeniedAsync(() => ReadAsync(fs, "\\incoming\\old.txt"));
        await AssertDeniedAsync(() => ReadAsync(fs, "//incoming/./old.txt"));
        await AssertDeniedAsync(() => ListAsync(fs, "/incoming/sub/.."));
    }

    [Fact]
    public async Task On_a_case_insensitive_storage_another_spelling_gets_the_same_rules()
    {
        await SeedAsync();
        var fs = Create(new() { ["/"] = FilePermissions.All, ["/incoming"] = FilePermissions.Upload },
            inner: new WithCapabilities(_backend, StorageCapabilities.CaseInsensitivePaths));

        await AssertDeniedAsync(() => ListAsync(fs, "/INCOMING"));
        await AssertDeniedAsync(() => ReadAsync(fs, "/Incoming./old.txt"));
    }

    // ---- Path filters ----

    private PermissionFileSystem Filtered() => Create(
        new() { ["/"] = FilePermissions.All },
        new()
        {
            ["/"] = new PathFilter { DeniedPatterns = ["*.exe"], HiddenPatterns = [".secret*"] },
            ["/incoming"] = new PathFilter { AllowedPatterns = ["*.csv"] },
        });

    [Fact]
    public async Task A_denied_pattern_cannot_be_uploaded_or_renamed_to()
    {
        await SeedAsync();
        var fs = Filtered();

        await AssertDeniedAsync(() => WriteAsync(fs, "/setup.exe", "x"));
        await AssertDeniedAsync(() => WriteAsync(fs, "/outgoing/SETUP.EXE", "x"));
        await AssertDeniedAsync(() => fs.RenameAsync("/outgoing/report.txt", "/outgoing/report.exe", RenameFlags.None, Ct).AsTask());
        await WriteAsync(fs, "/setup.txt", "x");
        Assert.Null(await _backend.StatAsync("/setup.exe", true, Ct));
        Assert.Null(await _backend.StatAsync("/outgoing/report.exe", true, Ct));
    }

    [Fact]
    public async Task Only_allowed_patterns_can_be_uploaded_where_an_allow_list_applies()
    {
        await SeedAsync();
        var fs = Filtered();

        await WriteAsync(fs, "/incoming/data.csv", "1;2");
        await WriteAsync(fs, "/incoming/sub/more.CSV", "1;2");
        await AssertDeniedAsync(() => WriteAsync(fs, "/incoming/data.txt", "x"));
        await AssertDeniedAsync(() => ReadAsync(fs, "/incoming/old.txt"));
        await AssertDeniedAsync(() => fs.DeleteFileAsync("/incoming/old.txt", Ct).AsTask());
        await fs.CreateDirectoryAsync("/incoming/dir", Ct); // the patterns are for files; directories are not filtered
    }

    [Fact]
    public async Task A_hidden_pattern_is_not_listed_and_does_not_exist()
    {
        await SeedAsync();
        await WriteAsync(_backend, "/outgoing/.secret.key", "key");
        await _backend.CreateDirectoryAsync("/.secrets", Ct);
        await WriteAsync(_backend, "/.secrets/a.txt", "a");
        var fs = Filtered();

        Assert.Equal(["report.txt"], (await ListAsync(fs, "/outgoing")).Select(e => e.Name));
        Assert.DoesNotContain(".secrets", (await ListAsync(fs, "/")).Select(e => e.Name));
        Assert.Null(await fs.StatAsync("/outgoing/.secret.key", true, Ct));
        Assert.Null(await fs.StatAsync("/.secrets/a.txt", true, Ct));
        await AssertNoSuchFileAsync(() => ReadAsync(fs, "/outgoing/.secret.key"));
        await AssertNoSuchFileAsync(() => ListAsync(fs, "/.secrets"));
        await AssertNoSuchFileAsync(() => fs.DeleteFileAsync("/outgoing/.secret.key", Ct).AsTask());
        await AssertNoSuchFileAsync(() => fs.RenameAsync("/outgoing/.secret.key", "/outgoing/key", RenameFlags.None, Ct).AsTask());
        await AssertNoSuchFileAsync(() => fs.RenameAsync("/outgoing/report.txt", "/outgoing/.secret2", RenameFlags.None, Ct).AsTask());
        await AssertNoSuchFileAsync(() => WriteAsync(fs, "/.secret-new", "x"));
        await AssertNoSuchFileAsync(() => fs.SetAttributesAsync("/outgoing/.secret.key", new FileAttributesUpdate { Size = 0 }, Ct).AsTask());
        Assert.Equal("key", await ReadAsync(_backend, "/outgoing/.secret.key"));
    }

    [Fact]
    public async Task Errors_from_the_backend_pass_through_unchanged()
    {
        var fs = Filtered();

        await AssertErrorAsync(FileSystemError.NoSuchFile, () => ReadAsync(fs, "/missing.txt"));
        await AssertErrorAsync(FileSystemError.NotADirectory, () => ListAsync(fs, "/x.txt"), seed: () => WriteAsync(_backend, "/x.txt", "x"));
    }

    // ---- Helpers ----

    private static async Task AssertErrorAsync(FileSystemError expected, Func<Task> action, Func<Task>? seed = null)
    {
        if (seed != null)
            await seed();
        var ex = await Assert.ThrowsAsync<FileSystemException>(action);
        Assert.Equal(expected, ex.Error);
    }

    private static Task AssertDeniedAsync(Func<Task> action) => AssertErrorAsync(FileSystemError.PermissionDenied, action);

    private static Task AssertNoSuchFileAsync(Func<Task> action) => AssertErrorAsync(FileSystemError.NoSuchFile, action);

    private static async Task WriteAsync(IFileSystem fs, string path, string content)
    {
        await using var handle = await fs.OpenAsync(path, WriteNew, null, Ct);
        await handle.WriteAsync(0, Encoding.UTF8.GetBytes(content), Ct);
    }

    private static async Task<string> ReadAsync(IFileSystem fs, string path)
    {
        await using var handle = await fs.OpenAsync(path, FileOpenFlags.Read, null, Ct);
        var buffer = new byte[4096];
        var read = await handle.ReadAsync(0, buffer, Ct);
        return Encoding.UTF8.GetString(buffer, 0, read);
    }

    private static async Task<List<FileSystemEntry>> ListAsync(IFileSystem fs, string path)
    {
        var entries = new List<FileSystemEntry>();
        await foreach (var entry in fs.ListAsync(path, Ct))
            entries.Add(entry);
        return entries;
    }

    /// <summary>Another client creates <paramref name="path"/> after the decorator checked that it does not exist.</summary>
    private sealed class FileAppearsOnOpen(IFileSystem inner, string path) : DelegatingFileSystem(inner)
    {
        public override async ValueTask<IFileHandle> OpenAsync(string openPath, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct)
        {
            if (VirtualPath.Normalize(openPath) == path && await Inner.StatAsync(path, true, ct) == null)
                await WriteAsync(Inner, path, "theirs");
            return await Inner.OpenAsync(openPath, flags, initial, ct);
        }
    }

    /// <summary>Declares extra capabilities (only to test how the decorator reads them).</summary>
    private sealed class WithCapabilities(IFileSystem inner, StorageCapabilities extra) : DelegatingFileSystem(inner)
    {
        public override StorageCapabilities Capabilities => Inner.Capabilities | extra;
    }

    private abstract class DelegatingFileSystem(IFileSystem inner) : IFileSystem
    {
        protected IFileSystem Inner { get; } = inner;
        public virtual StorageCapabilities Capabilities => Inner.Capabilities;
        public ValueTask<FileSystemEntry?> StatAsync(string path, bool followLinks, CancellationToken ct) => Inner.StatAsync(path, followLinks, ct);
        public IAsyncEnumerable<FileSystemEntry> ListAsync(string path, CancellationToken ct) => Inner.ListAsync(path, ct);
        public virtual ValueTask<IFileHandle> OpenAsync(string path, FileOpenFlags flags, FileAttributesUpdate? initial, CancellationToken ct) => Inner.OpenAsync(path, flags, initial, ct);
        public ValueTask CreateDirectoryAsync(string path, CancellationToken ct) => Inner.CreateDirectoryAsync(path, ct);
        public ValueTask DeleteFileAsync(string path, CancellationToken ct) => Inner.DeleteFileAsync(path, ct);
        public ValueTask DeleteDirectoryAsync(string path, CancellationToken ct) => Inner.DeleteDirectoryAsync(path, ct);
        public ValueTask RenameAsync(string oldPath, string newPath, RenameFlags flags, CancellationToken ct) => Inner.RenameAsync(oldPath, newPath, flags, ct);
        public ValueTask SetAttributesAsync(string path, FileAttributesUpdate update, CancellationToken ct) => Inner.SetAttributesAsync(path, update, ct);
        public ValueTask<StorageSpace?> GetStorageSpaceAsync(string path, CancellationToken ct) => Inner.GetStorageSpaceAsync(path, ct);
    }
}
