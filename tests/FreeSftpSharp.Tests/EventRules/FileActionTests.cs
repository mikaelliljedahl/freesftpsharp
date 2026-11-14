using System.IO.Compression;
using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.Storage;
using Microsoft.Extensions.Time.Testing;
using SshServer.EventRules;
using SshServer.EventRules.Actions;
using SshServer.Interfaces;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Permissions;
using FreeSftpSharp.Tests.Infrastructure;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.EventRules;

/// <summary>The file actions over the storage of the user (in memory), through the rules engine.</summary>
public sealed class FileActionTests : IAsyncDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _clock = new(Now);
    private readonly EventRuleTestHost _host;
    private readonly InMemoryFileSystem _files;

    public FileActionTests()
    {
        _host = new EventRuleTestHost(time: _clock);
        _host.AddUser("alice");
        _files = _host.Files.For("alice");
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public ValueTask DisposeAsync() => _host.DisposeAsync();

    private async Task<EventRuleRun> RunAsync(string path, params (string Type, Dictionary<string, string> Options)[] steps)
    {
        var id = await _host.AddRuleAsync(new EventRuleInput
        {
            Name = "files-" + Guid.NewGuid().ToString("N")[..6],
            Trigger = EventRuleTrigger.Event,
            EventTypes = ["File.Upload"],
            Actions = steps.Select(s => new EventRuleAction { Type = s.Type, Options = s.Options }).ToList(),
        });
        var rule = (await _host.Store.GetAsync(id, Ct))!;
        return await _host.Runner.RunForEventAsync(rule, EventRuleTestHost.Upload("alice", path), Ct);
    }

    [Fact]
    public async Task Move_renames_the_uploaded_file_and_creates_the_target_directory()
    {
        await MemoryFiles.WriteAsync(_files, "/incoming/report.csv", "data");

        var run = await RunAsync("/incoming/report.csv", ("Move", new() { ["Target"] = "/processed/{{Date}}/{{Name}}" }));

        Assert.Equal(EventRuleRunStatus.Ok, run.Status);
        Assert.False(await MemoryFiles.ExistsAsync(_files, "/incoming/report.csv"));
        Assert.Equal("data", await MemoryFiles.ReadAsync(_files, "/processed/2026-11-01/report.csv"));
        // The actions use the storage of the user as a server operation: no per-path permissions, an own protocol.
        var client = _host.Files.Clients.Last();
        Assert.True(client.SkipPermissions);
        Assert.Equal(EventRuleRunner.Protocol, client.Protocol);
    }

    [Fact]
    public async Task Move_does_not_replace_an_existing_file_unless_asked()
    {
        await MemoryFiles.WriteAsync(_files, "/a.txt", "new");
        await MemoryFiles.WriteAsync(_files, "/b.txt", "old");

        var refused = await RunAsync("/a.txt", ("Move", new() { ["Target"] = "/b.txt" }));
        Assert.Equal(EventRuleRunStatus.Failed, refused.Status);
        Assert.Equal("old", await MemoryFiles.ReadAsync(_files, "/b.txt"));

        var replaced = await RunAsync("/a.txt", ("Move", new() { ["Target"] = "/b.txt", ["Overwrite"] = "true" }));
        Assert.Equal(EventRuleRunStatus.Ok, replaced.Status);
        Assert.Equal("new", await MemoryFiles.ReadAsync(_files, "/b.txt"));
    }

    [Fact]
    public async Task Move_on_a_storage_without_rename_copies_and_deletes()
    {
        var noRename = new InMemoryFileSystem(StorageCapabilities.None);
        await using var host = new EventRuleTestHost(files: new SingleFileSystemFactory(noRename));
        host.AddUser("bob");
        await MemoryFiles.WriteAsync(noRename, "/in/x.bin", "payload");
        var id = await host.AddRuleAsync(new EventRuleInput
        {
            Name = "move", Trigger = EventRuleTrigger.Event, EventTypes = ["File.Upload"],
            Actions = [new EventRuleAction { Type = "Move", Options = new() { ["Target"] = "/out/{{Name}}" } }],
        });

        var run = await host.Runner.RunForEventAsync((await host.Store.GetAsync(id, Ct))!, EventRuleTestHost.Upload("bob", "/in/x.bin"), Ct);

        Assert.Equal(EventRuleRunStatus.Ok, run.Status);
        Assert.False(await MemoryFiles.ExistsAsync(noRename, "/in/x.bin"));
        Assert.Equal("payload", await MemoryFiles.ReadAsync(noRename, "/out/x.bin"));
    }

    [Fact]
    public async Task Copy_copies_a_file_and_a_directory_tree()
    {
        await MemoryFiles.WriteAsync(_files, "/in/a.txt", "a");
        await MemoryFiles.WriteAsync(_files, "/in/sub/b.txt", "b");

        var run = await RunAsync("/in/a.txt",
            ("Copy", new() { ["Target"] = "/backup/{{Name}}" }),
            ("Copy", new() { ["Source"] = "/in", ["Target"] = "/tree" }));

        Assert.Equal(EventRuleRunStatus.Ok, run.Status);
        Assert.Equal("a", await MemoryFiles.ReadAsync(_files, "/in/a.txt"));
        Assert.Equal("a", await MemoryFiles.ReadAsync(_files, "/backup/a.txt"));
        Assert.Equal("b", await MemoryFiles.ReadAsync(_files, "/tree/sub/b.txt"));
        Assert.Contains("(2 files)", run.Message);
    }

    [Fact]
    public async Task Delete_removes_files_and_a_directory_only_with_its_content_when_asked()
    {
        await MemoryFiles.WriteAsync(_files, "/tmp/a.txt", "a");
        await MemoryFiles.WriteAsync(_files, "/old/b.txt", "b");

        var file = await RunAsync("/tmp/a.txt", ("Delete", new()));
        Assert.Equal(EventRuleRunStatus.Ok, file.Status);
        Assert.False(await MemoryFiles.ExistsAsync(_files, "/tmp/a.txt"));

        var notEmpty = await RunAsync("/x", ("Delete", new() { ["Paths"] = "/old" }));
        Assert.Equal(EventRuleRunStatus.Failed, notEmpty.Status);
        Assert.True(await MemoryFiles.ExistsAsync(_files, "/old/b.txt"));

        var recursive = await RunAsync("/x", ("Delete", new() { ["Paths"] = "/old", ["Recursive"] = "true" }));
        Assert.Equal(EventRuleRunStatus.Ok, recursive.Status);
        Assert.False(await MemoryFiles.ExistsAsync(_files, "/old"));

        var root = await RunAsync("/x", ("Delete", new() { ["Paths"] = "/../..", ["Recursive"] = "true" }));
        Assert.Equal(EventRuleRunStatus.Failed, root.Status);
        Assert.Contains("never removed", root.Message);
    }

    [Fact]
    public async Task CreateDirectory_and_Exists()
    {
        var run = await RunAsync("/x",
            ("CreateDirectory", new() { ["Paths"] = "/a/b/c\n/{{Username}}" }),
            ("Exists", new() { ["Paths"] = "/a/b/c\n/alice" }));
        Assert.Equal(EventRuleRunStatus.Ok, run.Status);

        var missing = await RunAsync("/x", ("Exists", new() { ["Paths"] = "/a\n/nothing" }));
        Assert.Equal(EventRuleRunStatus.Failed, missing.Status);
        Assert.Contains("Missing: /nothing", missing.Message);
    }

    [Fact]
    public async Task Compress_writes_a_zip_with_the_files()
    {
        await MemoryFiles.WriteAsync(_files, "/in/a.txt", "alpha");
        await MemoryFiles.WriteAsync(_files, "/in/sub/b.txt", "beta");

        var run = await RunAsync("/in/a.txt", ("Compress", new() { ["Paths"] = "/in", ["Archive"] = "/archive/{{Username}}.zip" }));

        Assert.Equal(EventRuleRunStatus.Ok, run.Status);
        var bytes = await FileOperations.ReadAllAsync(_files, "/archive/alice.zip", long.MaxValue, Ct);
        using var zip = new ZipArchive(new MemoryStream(bytes!), ZipArchiveMode.Read);
        var names = zip.Entries.Select(e => e.FullName).ToHashSet();
        Assert.Contains("in/a.txt", names);
        Assert.Contains("in/sub/b.txt", names);
        using var reader = new StreamReader(zip.GetEntry("in/sub/b.txt")!.Open());
        Assert.Equal("beta", await reader.ReadToEndAsync(Ct));
    }

    [Fact]
    public async Task Retention_removes_only_the_files_older_than_the_limit_and_reports_the_count()
    {
        var old = Now.UtcDateTime - TimeSpan.FromDays(31);
        var recent = Now.UtcDateTime - TimeSpan.FromDays(29);
        await MemoryFiles.WriteAsync(_files, "/tmp/old.txt", "x", old);
        await MemoryFiles.WriteAsync(_files, "/tmp/deep/old.txt", "x", old);
        await MemoryFiles.WriteAsync(_files, "/tmp/new.txt", "x", recent);
        await MemoryFiles.WriteAsync(_files, "/keep/old.txt", "x", old);
        _host.Emails.IsConfigured = true;

        var run = await RunAsync("/x",
            ("Retention", new() { ["Folders"] = "/tmp", ["RetainDays"] = "30", ["DeleteEmptyDirectories"] = "true" }),
            ("Email", new() { ["To"] = "ops@example.com", ["Subject"] = "Retention: {{RetentionDeleted}} files", ["Body"] = "{{RetentionReport}}" }));

        Assert.Equal(EventRuleRunStatus.Ok, run.Status);
        Assert.False(await MemoryFiles.ExistsAsync(_files, "/tmp/old.txt"));
        Assert.False(await MemoryFiles.ExistsAsync(_files, "/tmp/deep"));
        Assert.True(await MemoryFiles.ExistsAsync(_files, "/tmp/new.txt"));
        Assert.True(await MemoryFiles.ExistsAsync(_files, "/keep/old.txt"));
        Assert.True(await MemoryFiles.ExistsAsync(_files, "/tmp"));
        var mail = Assert.Single(_host.Emails.Sent);
        Assert.Equal("Retention: 2 files", mail.Subject);
        Assert.Contains("alice: removed 2 files older than 30 days in /tmp and 1 empty directories.", mail.Body);
    }

    [Fact]
    public async Task The_storage_factory_leaves_out_the_permissions_for_a_server_operation_only()
    {
        var user = new User
        {
            Username = "limited",
            UserRootDirectory = "/unused",
            Permissions = new() { ["/"] = FilePermissions.List | FilePermissions.Download },
        };
        var backend = new InMemoryFileSystem();
        var factory = TestStorage.Factory([new FixedProvider(backend)], codec => TestStorage.Fixed(codec, "memory", new MemoryOptions()),
            events: new RecordingEventBus());

        var client = await factory.CreateAsync(user, new ClientContext("SFTP", "192.0.2.1"), Ct);
        var server = await factory.CreateAsync(user, new ClientContext(EventRuleRunner.Protocol, null) { SkipPermissions = true }, Ct);

        var refused = await Assert.ThrowsAsync<FileSystemException>(() => client.CreateDirectoryAsync("/made", Ct).AsTask());
        Assert.Equal(FileSystemError.PermissionDenied, refused.Error);
        await server.CreateDirectoryAsync("/made", Ct);
        Assert.True(await MemoryFiles.ExistsAsync(backend, "/made"));
    }

    private sealed class SingleFileSystemFactory(IFileSystem fileSystem) : IFileSystemFactory
    {
        public ValueTask<IFileSystem> CreateAsync(User user, ClientContext client, CancellationToken ct) => ValueTask.FromResult(fileSystem);
    }

    public sealed class MemoryOptions
    {
    }

    private sealed class FixedProvider(IFileSystem fileSystem) : StorageProvider<MemoryOptions>
    {
        public override string Name => "memory";

        protected override IReadOnlyList<string> ValidateOptions(MemoryOptions options) => [];

        protected override ValueTask<IFileSystem> CreateFileSystemAsync(MemoryOptions options, CancellationToken ct) => ValueTask.FromResult(fileSystem);
    }
}
