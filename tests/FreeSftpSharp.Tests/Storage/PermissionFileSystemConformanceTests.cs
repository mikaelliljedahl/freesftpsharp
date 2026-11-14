using System.Reflection;
using SshServer.Interfaces;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Storage;

/// <summary>
/// The conformance suite through <see cref="PermissionFileSystem"/> with rules that allow everything: the decorator
/// must be invisible (same results, same errors) when the user may do everything.
/// </summary>
public sealed class PermissionFileSystemConformanceTests : FileSystemConformanceTests<PermissionFileSystemConformanceTests.Fixture>
{
    public sealed class Fixture : IFileSystemFixture
    {
        // An extra entry with All keeps the decorator in the chain (PermissionFileSystem.Wrap would leave it out).
        private static readonly EffectivePermissions AllowEverything = new(
            new Dictionary<string, FilePermissions> { ["/"] = FilePermissions.All, ["/zz-unused"] = FilePermissions.All },
            new Dictionary<string, PathFilter> { ["/"] = new PathFilter { DeniedPatterns = ["never-used-name"] } });

        public IFileSystem FileSystem { get; } = new PermissionFileSystem(new InMemoryFileSystem(), AllowEverything);
        public StorageCapabilities ExpectedCapabilities => InMemoryFileSystem.AllCapabilities;
        public void Dispose() { }
    }
}

/// <summary>
/// The decorator in "deny everything" mode (<c>/ = None</c>): every operation of <see cref="IFileSystem"/> and of the
/// open handle fails with <see cref="FileSystemError.PermissionDenied"/>, and nothing reaches the backend.
/// </summary>
public sealed class PermissionFileSystemDenyEverythingTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly EffectivePermissions DenyEverything = new(
        new Dictionary<string, FilePermissions> { ["/"] = FilePermissions.None },
        new Dictionary<string, PathFilter>());

    /// <summary>Every operation of <see cref="IFileSystem"/>, on an existing and on a missing path.</summary>
    public static TheoryData<string, string> Operations()
    {
        var data = new TheoryData<string, string>();
        foreach (var name in OperationsByName.Keys)
        {
            data.Add(name, "/existing.txt");
            data.Add(name, "/dir");
            data.Add(name, "/missing");
            data.Add(name, "/");
        }
        return data;
    }

    private static readonly Dictionary<string, Func<IFileSystem, string, Task>[]> OperationsByName = new()
    {
        [nameof(IFileSystem.StatAsync)] = [async (fs, p) => await fs.StatAsync(p, true, Ct), async (fs, p) => await fs.StatAsync(p, false, Ct)],
        [nameof(IFileSystem.ListAsync)] = [async (fs, p) => { await foreach (var _ in fs.ListAsync(p, Ct)) { } }],
        [nameof(IFileSystem.OpenAsync)] =
        [
            async (fs, p) => await fs.OpenAsync(p, FileOpenFlags.Read, null, Ct),
            async (fs, p) => await fs.OpenAsync(p, FileOpenFlags.Write, null, Ct),
            async (fs, p) => await fs.OpenAsync(p, FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate, null, Ct),
            async (fs, p) => await fs.OpenAsync(p, FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Exclusive, null, Ct),
            async (fs, p) => await fs.OpenAsync(p, FileOpenFlags.Write | FileOpenFlags.Append, null, Ct),
            async (fs, p) => await fs.OpenAsync(p, FileOpenFlags.Read | FileOpenFlags.Write | FileOpenFlags.Create, null, Ct),
        ],
        [nameof(IFileSystem.CreateDirectoryAsync)] = [async (fs, p) => await fs.CreateDirectoryAsync(p + "-new", Ct)],
        [nameof(IFileSystem.DeleteFileAsync)] = [async (fs, p) => await fs.DeleteFileAsync(p, Ct)],
        [nameof(IFileSystem.DeleteDirectoryAsync)] = [async (fs, p) => await fs.DeleteDirectoryAsync(p, Ct)],
        [nameof(IFileSystem.RenameAsync)] =
        [
            async (fs, p) => await fs.RenameAsync(p, "/renamed", RenameFlags.None, Ct),
            async (fs, p) => await fs.RenameAsync(p, "/renamed", RenameFlags.ReplaceExisting, Ct),
        ],
        [nameof(IFileSystem.SetAttributesAsync)] =
        [
            async (fs, p) => await fs.SetAttributesAsync(p, new FileAttributesUpdate(), Ct),
            async (fs, p) => await fs.SetAttributesAsync(p, new FileAttributesUpdate { Size = 0 }, Ct),
            async (fs, p) => await fs.SetAttributesAsync(p, new FileAttributesUpdate { Permissions = 0x1FF }, Ct),
            async (fs, p) => await fs.SetAttributesAsync(p, new FileAttributesUpdate { LastWriteTimeUtc = DateTime.UtcNow }, Ct),
        ],
        [nameof(IFileSystem.GetStorageSpaceAsync)] = [async (fs, p) => await fs.GetStorageSpaceAsync(p, Ct)],
    };

    [Fact]
    public void Every_operation_of_the_interface_is_covered()
    {
        var methods = typeof(IFileSystem).GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => !m.IsSpecialName) // the Capabilities property is not an operation
            .Select(m => m.Name);

        Assert.Equal(methods.Order(), OperationsByName.Keys.Order());
    }

    [Theory]
    [MemberData(nameof(Operations))]
    public async Task Every_operation_is_denied_and_does_not_reach_the_backend(string operation, string path)
    {
        var (fs, recorder) = await CreateAsync();

        foreach (var call in OperationsByName[operation])
        {
            var ex = await Assert.ThrowsAsync<FileSystemException>(() => call(fs, path));
            Assert.Equal(FileSystemError.PermissionDenied, ex.Error);
        }

        Assert.Empty(recorder.Calls);
    }

    [Fact]
    public async Task Wrap_leaves_out_the_decorator_only_for_an_unrestricted_user()
    {
        var inner = new InMemoryFileSystem();

        Assert.Same(inner, PermissionFileSystem.Wrap(inner, EffectivePermissions.Unrestricted));
        Assert.IsType<PermissionFileSystem>(PermissionFileSystem.Wrap(inner, DenyEverything));
        await Task.CompletedTask;
    }

    private static async Task<(IFileSystem Fs, RecordingFileSystem Recorder)> CreateAsync()
    {
        var backend = new InMemoryFileSystem();
        await backend.CreateDirectoryAsync("/dir", Ct);
        await (await backend.OpenAsync("/existing.txt", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct)).DisposeAsync();
        var recorder = new RecordingFileSystem(backend);
        return (new PermissionFileSystem(recorder, DenyEverything), recorder);
    }
}
