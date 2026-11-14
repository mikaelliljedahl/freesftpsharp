using System.Security.Cryptography;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Storage.Gcs;
using Renci.SshNet;
using SshServer.Filesystem.Gcs;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;
using static FreeSftpSharp.Tests.Infrastructure.OpenSshSftp;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// The server with the GCS backend as the storage of every user, against a Cloud Storage emulator (fake-gcs-server in
/// CI); skipped unless FREESFTPSHARP_TEST_GCS_ENDPOINT is set. The fixture gives every user "gcs" with a fixed
/// <see cref="IUserStorageResolver"/>.
/// </summary>
public sealed class GcsSftpServerFixture : SftpServerFixture
{
    public string KeyPrefix { get; } = "e2e/" + Guid.NewGuid().ToString("N");

    protected override IFileSystemFactory CreateFileSystemFactory(IConnectionRegistry connections, IEventBus? events, ISettingsRepository repository)
    {
        if (GcsTestServer.Endpoint != null)
            GcsTestServer.EnsureBucket(); // on a new emulator (CI) the bucket is missing
        return TestStorage.Factory([new GcsStorageProvider(new GcsClientCache())],
            codec => TestStorage.Fixed(codec, GcsStorageProvider.ProviderName, GcsTestServer.Options(KeyPrefix)), connections, events);
    }

    /// <summary>The object names below the user root of this fixture.</summary>
    public List<string> ObjectNames() => GcsTestServer.ObjectNames(KeyPrefix);

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        if (GcsTestServer.Endpoint != null)
            GcsTestServer.DeletePrefix(KeyPrefix);
    }
}

[Trait("Category", "Gcs")]
public sealed class GcsEndToEndTests : IClassFixture<GcsSftpServerFixture>
{
    private const int MiB = 1024 * 1024;

    private readonly GcsSftpServerFixture _server;

    public GcsEndToEndTests(GcsSftpServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task OpenSsh_upload_of_40_MiB_is_one_object_and_SshNet_downloads_the_same_bytes()
    {
        GcsTestServer.SkipIfUnavailable();
        SkipIfUnavailable();
        var local = Directory.CreateTempSubdirectory("freesftpsharp-gcs-").FullName;
        try
        {
            var content = RandomNumberGenerator.GetBytes(40 * MiB);
            var file = Path.Combine(local, "big.bin");
            await File.WriteAllBytesAsync(file, content, TestContext.Current.CancellationToken);

            var result = await RunAsync(_server, local, "mkdir up", $"put {Quote(file)} up/big.bin", "pwd");
            Assert.Contains("Remote working directory: /", result.AllOutput);

            Assert.Contains(_server.KeyPrefix + "/up/big.bin", _server.ObjectNames());
            using var client = _server.Connect();
            Assert.Equal(content.Length, client.GetAttributes("/up/big.bin").Size);
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
    public void SshNet_file_operations_work_on_GCS()
    {
        GcsTestServer.SkipIfUnavailable();
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
    public async Task Lost_connection_during_an_upload_leaves_no_object()
    {
        GcsTestServer.SkipIfUnavailable();
        var proxy = new SlowDownstreamProxy(_server.Port, pauseMilliseconds: 0);
        var client = new SftpClient(SftpServerFixture.Host, proxy.Port, _server.Username, _server.Password);
        try
        {
            client.Connect();
            var stream = client.Create("/lost.bin");
            stream.Write(RandomNumberGenerator.GetBytes(20 * MiB)); // two chunks of 8 MiB are sent, the rest is buffered
            stream.Flush();

            await proxy.DisposeAsync(); // the TCP connection is lost; the client sends nothing more

            await Task.Delay(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken); // the server notices the loss and aborts the upload
            Assert.DoesNotContain(_server.KeyPrefix + "/lost.bin", _server.ObjectNames());
        }
        finally
        {
            try { client.Dispose(); } catch { /* the connection is gone */ }
            await proxy.DisposeAsync();
        }
    }
}
