using FreeSftpSharp.Tests.Storage;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Storage;
using SshServerModule.Connections;

namespace FreeSftpSharp.Tests.Connections;

/// <summary>
/// The storage decorator that keeps the registry entry of one connection up to date
/// (<see cref="ConnectionTrackingFileSystem"/>), on <see cref="InMemoryFileSystem"/>.
/// </summary>
public sealed class ConnectionTrackingFileSystemTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly FakeTimeProvider _time = new(Start);
    private readonly ConnectionRegistry _registry;
    private readonly Guid _id;
    private readonly ConnectionTrackingFileSystem _fileSystem;

    public ConnectionTrackingFileSystemTests()
    {
        _registry = new ConnectionRegistry(_time);
        _id = _registry.Register(new ConnectionRegistration(ConnectionProtocols.Sftp, "127.0.0.1:1", _ => Task.CompletedTask)).Id;
        _fileSystem = new ConnectionTrackingFileSystem(new InMemoryFileSystem(), _registry, _id);
    }

    private ConnectionInfo Connection => _registry.Get(_id)!;

    [Fact]
    public async Task Writes_of_an_open_file_are_an_upload_with_the_bytes_so_far()
    {
        var handle = await _fileSystem.OpenAsync("dir/../up.bin", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct);
        Assert.Empty(Connection.Transfers); // no transfer before the first byte

        await handle.WriteAsync(0, new byte[100], Ct);
        await handle.WriteAsync(100, new byte[50], Ct);

        var transfer = Assert.Single(Connection.Transfers);
        Assert.Equal("/up.bin", transfer.VirtualPath);
        Assert.Equal(TransferDirection.Upload, transfer.Direction);
        Assert.Equal(150, transfer.Bytes);

        await handle.DisposeAsync();

        Assert.Empty(Connection.Transfers);
        var entry = await _fileSystem.StatAsync("/up.bin", true, Ct);
        Assert.Equal(150, entry!.Size);
    }

    [Fact]
    public async Task Reads_of_an_open_file_are_a_download()
    {
        await using (var write = await _fileSystem.OpenAsync("/down.bin", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct))
            await write.WriteAsync(0, new byte[300], Ct);

        await using var handle = await _fileSystem.OpenAsync("/down.bin", FileOpenFlags.Read, null, Ct);
        var read = await handle.ReadAsync(0, new byte[200], Ct);

        var transfer = Assert.Single(Connection.Transfers);
        Assert.Equal(TransferDirection.Download, transfer.Direction);
        Assert.Equal(read, transfer.Bytes);
    }

    [Fact]
    public async Task Every_operation_records_activity()
    {
        _time.Advance(TimeSpan.FromMinutes(1));
        await _fileSystem.CreateDirectoryAsync("/d", Ct);
        Assert.Equal(Start.AddMinutes(1), Connection.LastActivity);

        _time.Advance(TimeSpan.FromMinutes(1));
        await foreach (var _ in _fileSystem.ListAsync("/", Ct))
        {
        }
        Assert.Equal(Start.AddMinutes(2), Connection.LastActivity);
    }

    [Fact]
    public async Task Errors_of_the_storage_are_unchanged_and_start_no_transfer()
    {
        var error = await Assert.ThrowsAsync<FileSystemException>(async () =>
            await _fileSystem.OpenAsync("/missing", FileOpenFlags.Read, null, Ct));

        Assert.Equal(FileSystemError.NoSuchFile, error.Error);
        Assert.Empty(Connection.Transfers);
    }
}
