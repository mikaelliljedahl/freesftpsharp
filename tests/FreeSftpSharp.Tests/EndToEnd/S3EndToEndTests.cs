using System.Security.Cryptography;
using Amazon.S3.Model;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Storage.S3;
using Renci.SshNet;
using SshServer.Filesystem.S3;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;
using static FreeSftpSharp.Tests.Infrastructure.OpenSshSftp;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// The server with the S3 backend as the storage of every user, against a real S3 server (MinIO in CI); skipped unless
/// FREESFTPSHARP_TEST_S3_ENDPOINT is set. Until the per-user storage configuration (#56), the fixture selects "s3"
/// with its own <see cref="IUserStorageResolver"/>.
/// </summary>
public sealed class S3SftpServerFixture : SftpServerFixture
{
    public string KeyPrefix { get; } = "e2e/" + Guid.NewGuid().ToString("N");

    protected override IFileSystemFactory CreateFileSystemFactory(IConnectionRegistry connections, IEventBus? events, ISettingsRepository repository)
    {
        if (S3TestServer.Endpoint != null)
            S3TestServer.EnsureBucket(); // this fixture has its own client; on a new S3 server the bucket is missing
        return TestStorage.Factory([new S3StorageProvider(new S3ClientCache())],
            codec => TestStorage.Fixed(codec, S3StorageProvider.ProviderName, S3TestServer.Options(KeyPrefix)), connections, events);
    }

    /// <summary>The object key of a virtual path such as "/dir/a.txt".</summary>
    public string Key(string virtualPath) => KeyPrefix + virtualPath;

    /// <summary>The object of a virtual path, or null.</summary>
    public async Task<GetObjectMetadataResponse?> HeadAsync(string virtualPath)
    {
        try
        {
            return await S3TestServer.Client.GetObjectMetadataAsync(S3TestServer.Bucket, Key(virtualPath));
        }
        catch (Amazon.S3.AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        if (S3TestServer.Endpoint != null)
            S3TestServer.DeletePrefix(KeyPrefix);
    }
}

[Trait("Category", "S3")]
public sealed class S3EndToEndTests : IClassFixture<S3SftpServerFixture>
{
    private const int MiB = 1024 * 1024;

    private readonly S3SftpServerFixture _server;

    public S3EndToEndTests(S3SftpServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task OpenSsh_upload_of_100_MiB_is_one_multipart_object_and_SshNet_downloads_the_same_bytes()
    {
        S3TestServer.SkipIfUnavailable();
        SkipIfUnavailable();
        var local = Directory.CreateTempSubdirectory("freesftpsharp-s3-").FullName;
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
            Assert.Equal(MultipartETag(content, 5 * MiB), head.ETag); // 20 parts of the default 5 MiB
            Assert.Equal(0, await S3TestServer.CountOpenUploadsAsync(_server.Key("/up/big.bin")));

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
    public void SshNet_file_operations_work_on_S3()
    {
        S3TestServer.SkipIfUnavailable();
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
    public async Task Lost_connection_during_an_upload_leaves_no_object_and_no_multipart_upload()
    {
        S3TestServer.SkipIfUnavailable();
        var proxy = new SlowDownstreamProxy(_server.Port, pauseMilliseconds: 0);
        var client = new SftpClient(SftpServerFixture.Host, proxy.Port, _server.Username, _server.Password);
        try
        {
            client.Connect();
            var stream = client.Create("/lost.bin");
            stream.Write(RandomNumberGenerator.GetBytes(12 * MiB)); // two parts are sent, the rest is buffered
            stream.Flush();
            Assert.True(await WaitUntilAsync(async () => await S3TestServer.CountOpenUploadsAsync(_server.Key("/lost.bin")) > 0), "The upload did not start.");

            await proxy.DisposeAsync(); // the TCP connection is lost; the client sends nothing more

            Assert.True(await WaitUntilAsync(async () => await S3TestServer.CountOpenUploadsAsync(_server.Key("/lost.bin")) == 0), "The multipart upload is still open.");
            Assert.Null(await _server.HeadAsync("/lost.bin"));
        }
        finally
        {
            try { client.Dispose(); } catch { /* the connection is gone */ }
            await proxy.DisposeAsync();
        }
    }

    /// <summary>The ETag of S3 for a multipart upload: the MD5 of the MD5s of the parts, a dash and the number of parts.</summary>
    private static string MultipartETag(byte[] content, int partSize)
    {
        using var md5s = new MemoryStream();
        var parts = 0;
        for (var offset = 0; offset < content.Length; offset += partSize, parts++)
            md5s.Write(MD5.HashData(content.AsSpan(offset, Math.Min(partSize, content.Length - offset))));
        return $"\"{Convert.ToHexStringLower(MD5.HashData(md5s.ToArray()))}-{parts}\"";
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
