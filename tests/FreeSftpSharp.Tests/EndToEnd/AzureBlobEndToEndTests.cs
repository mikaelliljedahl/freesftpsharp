using System.Security.Cryptography;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Storage.AzureBlob;
using Renci.SshNet;
using SshServer.Filesystem.AzureBlob;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;
using static FreeSftpSharp.Tests.Infrastructure.OpenSshSftp;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// The server with the Azure Blob backend as the storage of every user, against Azurite; skipped unless
/// FREESFTPSHARP_TEST_AZURITE is set. The fixture gives every user "azure-blob" with a fixed
/// <see cref="IUserStorageResolver"/>.
/// </summary>
public sealed class AzureBlobSftpServerFixture : SftpServerFixture
{
    public string KeyPrefix { get; } = "e2e/" + Guid.NewGuid().ToString("N");

    protected override IFileSystemFactory CreateFileSystemFactory(IConnectionRegistry connections, IEventBus? events, ISettingsRepository repository)
    {
        if (AzuriteTestServer.Endpoint != null)
            AzuriteTestServer.EnsureContainer(); // on a new Azurite the container is missing
        var options = AzuriteTestServer.Endpoint == null ? new AzureBlobStorageOptions() : AzuriteTestServer.Options(KeyPrefix);
        return TestStorage.Factory([new AzureBlobStorageProvider(new AzureBlobClientCache())],
            codec => TestStorage.Fixed(codec, AzureBlobStorageProvider.ProviderName, options), connections, events);
    }

    /// <summary>The blob name of a virtual path such as "/dir/a.txt".</summary>
    public string BlobName(string virtualPath) => KeyPrefix + virtualPath;

    /// <summary>The committed blob of a virtual path, or null.</summary>
    public async Task<BlobProperties?> HeadAsync(string virtualPath)
    {
        var blob = AzuriteTestServer.Client.GetBlobClient(BlobName(virtualPath));
        return await blob.ExistsAsync() ? (await blob.GetPropertiesAsync()).Value : null;
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        if (AzuriteTestServer.Endpoint != null)
            AzuriteTestServer.DeletePrefix(KeyPrefix);
    }
}

[Trait("Category", "Azure")]
public sealed class AzureBlobEndToEndTests : IClassFixture<AzureBlobSftpServerFixture>
{
    private const int MiB = 1024 * 1024;

    private readonly AzureBlobSftpServerFixture _server;

    public AzureBlobEndToEndTests(AzureBlobSftpServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task OpenSsh_upload_of_100_MiB_is_one_block_blob_and_SshNet_downloads_the_same_bytes()
    {
        AzuriteTestServer.SkipIfUnavailable();
        SkipIfUnavailable();
        var local = Directory.CreateTempSubdirectory("freesftpsharp-azure-").FullName;
        try
        {
            var content = RandomNumberGenerator.GetBytes(100 * MiB);
            var file = Path.Combine(local, "big.bin");
            await File.WriteAllBytesAsync(file, content, TestContext.Current.CancellationToken);

            var result = await RunAsync(_server, local, "mkdir up", $"put {Quote(file)} up/big.bin", "pwd");
            Assert.Contains("Remote working directory: /", result.AllOutput);

            var head = await _server.HeadAsync("/up/big.bin");
            Assert.NotNull(head);
            Assert.Equal(content.Length, head.ContentLength);
            var blocks = (await AzuriteTestServer.Client.GetBlockBlobClient(_server.BlobName("/up/big.bin")).GetBlockListAsync(BlockListTypes.Committed, cancellationToken: TestContext.Current.CancellationToken)).Value.CommittedBlocks;
            Assert.Equal(25, blocks.Count()); // 25 blocks of the default 4 MiB
            Assert.All(blocks, b => Assert.Equal(4 * MiB, b.SizeLong));
            Assert.Equal(0, await AzuriteTestServer.CountUncommittedBlocksAsync(_server.BlobName("/up/big.bin")));

            using var client = _server.Connect();
            using var download = new MemoryStream();
            client.DownloadFile("/up/big.bin", download);
            Assert.True(content.AsSpan().SequenceEqual(download.ToArray()), "The download differs from the upload.");
        }
        finally
        {
            Directory.Delete(local, recursive: true);
        }
    }

    [Fact]
    public void SshNet_file_operations_work_on_Azure_Blob()
    {
        AzuriteTestServer.SkipIfUnavailable();
        using var client = _server.Connect();
        var dir = "/ops-" + Guid.NewGuid().ToString("N");

        client.CreateDirectory(dir);
        client.UploadFile(new MemoryStream("hello"u8.ToArray()), dir + "/a.txt");
        client.RenameFile(dir + "/a.txt", dir + "/b.txt");

        Assert.Equal(["b.txt"], client.ListDirectory(dir).Select(f => f.Name).Where(n => n is not ("." or "..")));
        Assert.Equal(5, client.GetAttributes(dir + "/b.txt").Size);
        using (var download = new MemoryStream())
        {
            client.DownloadFile(dir + "/b.txt", download);
            Assert.Equal("hello"u8.ToArray(), download.ToArray());
        }
        client.DeleteFile(dir + "/b.txt");
        client.DeleteDirectory(dir);
        Assert.False(client.Exists(dir));
    }

    [Fact]
    public async Task Lost_connection_during_an_upload_leaves_no_blob()
    {
        AzuriteTestServer.SkipIfUnavailable();
        var proxy = new SlowDownstreamProxy(_server.Port, pauseMilliseconds: 0);
        var client = new SftpClient(SftpServerFixture.Host, proxy.Port, _server.Username, _server.Password);
        var name = _server.BlobName("/lost.bin");
        try
        {
            client.Connect();
            var stream = client.Create("/lost.bin");
            stream.Write(RandomNumberGenerator.GetBytes(10 * MiB)); // two blocks are sent, the rest is buffered
            stream.Flush();
            Assert.True(await WaitUntilAsync(async () => await AzuriteTestServer.CountUncommittedBlocksAsync(name) > 0), "The upload did not start.");

            await proxy.DisposeAsync(); // the TCP connection is lost; the client sends nothing more

            await Task.Delay(1500, TestContext.Current.CancellationToken); // the server notices the lost connection and closes the file
            Assert.Null(await _server.HeadAsync("/lost.bin"));
            Assert.DoesNotContain(name, AzuriteTestServer.BlobNames(_server.KeyPrefix));
        }
        finally
        {
            try { client.Dispose(); } catch { /* the connection is gone */ }
            await proxy.DisposeAsync();
        }
    }

    private static async Task<bool> WaitUntilAsync(Func<Task<bool>> condition)
    {
        for (var i = 0; i < 100; i++)
        {
            if (await condition())
                return true;
            await Task.Delay(100);
        }
        return await condition();
    }
}
