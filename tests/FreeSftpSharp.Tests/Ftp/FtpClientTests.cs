using System.Diagnostics;
using FluentFTP;
using FluentFTP.Exceptions;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Ftp;

/// <summary>FluentFTP against the FTP server over FTPS (explicit TLS) and plain FTP (issue #72).</summary>
public sealed class FtpClientTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static byte[] Data(int size)
    {
        var data = new byte[size];
        new Random(size).NextBytes(data);
        return data;
    }

    [Theory]
    [InlineData(FtpDataConnectionType.EPSV)]
    [InlineData(FtpDataConnectionType.PASV)]
    public async Task List_upload_download_rename_and_delete_over_ftps(FtpDataConnectionType mode)
    {
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("alice");
        await using var client = host.Client("alice", mode: mode);
        await client.Connect(Ct);
        Assert.True(client.IsEncrypted);

        var data = Data(300 * 1024);
        Assert.Equal(FtpStatus.Success, await client.UploadBytes(data, "/docs/report.bin", FtpRemoteExists.Overwrite, createRemoteDir: true, token: Ct));
        Assert.Equal(data, await host.StorageOf("alice").ReadAllAsync("/docs/report.bin"));
        Assert.Equal(data.Length, await client.GetFileSize("/docs/report.bin", -1, Ct));

        var listing = await client.GetListing("/docs", Ct);
        var item = Assert.Single(listing);
        Assert.Equal("report.bin", item.Name);
        Assert.Equal(FtpObjectType.File, item.Type);
        Assert.Equal(data.Length, item.Size);

        Assert.Equal(data, await client.DownloadBytes("/docs/report.bin", Ct));

        await client.Rename("/docs/report.bin", "/docs/renamed.bin", Ct);
        Assert.False(await client.FileExists("/docs/report.bin", Ct));
        Assert.True(await client.FileExists("/docs/renamed.bin", Ct));

        await client.DeleteFile("/docs/renamed.bin", Ct);
        await client.DeleteDirectory("/docs", Ct);
        Assert.Empty(await client.GetListing("/", Ct));
    }

    [Fact]
    public async Task Uploads_and_downloads_resume_at_the_offset()
    {
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("alice");
        var data = Data(200 * 1024);
        await host.StorageOf("alice").WriteAllAsync("/big.bin", data[..(64 * 1024)]);
        await using var client = host.Client("alice");
        await client.Connect(Ct);

        // FluentFTP asks SIZE and sends REST 65536 before the STOR.
        using (var upload = new MemoryStream(data))
            Assert.Equal(FtpStatus.Success, await client.UploadStream(upload, "/big.bin", FtpRemoteExists.Resume, token: Ct));
        Assert.Equal(data, await host.StorageOf("alice").ReadAllAsync("/big.bin"));

        using var download = new MemoryStream();
        Assert.True(await client.DownloadStream(download, "/big.bin", 150 * 1024, token: Ct));
        Assert.Equal(data[(150 * 1024)..], download.ToArray());
    }

    [Fact]
    public async Task Appe_appends_and_mkd_cwd_pwd_work()
    {
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("alice");
        await host.StorageOf("alice").WriteAllAsync("/log.txt", "one\n");
        await using var client = host.Client("alice");
        await client.Connect(Ct);

        using (var more = new MemoryStream("two\n"u8.ToArray()))
            Assert.Equal(FtpStatus.Success, await client.UploadStream(more, "/log.txt", FtpRemoteExists.AddToEnd, token: Ct));
        Assert.Equal("one\ntwo\n", await host.StorageOf("alice").ReadAllTextAsync("/log.txt"));

        await client.CreateDirectory("/a b", Ct);
        await client.SetWorkingDirectory("/a b", Ct);
        Assert.Equal("/a b", await client.GetWorkingDirectory(Ct));
        Assert.Equal(FtpStatus.Success, await client.UploadBytes("x"u8.ToArray(), "relative.txt", token: Ct));
        Assert.Equal("x", await host.StorageOf("alice").ReadAllTextAsync("/a b/relative.txt"));
        Assert.True((await client.GetModifiedTime("/a b/relative.txt", Ct)) > DateTime.MinValue);
    }

    [Fact]
    public async Task Paths_stay_in_the_user_root()
    {
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("alice");
        await host.StorageOf("alice").WriteAllAsync("/inside.txt", "in");
        await using var client = host.Client("alice");
        client.Config.SanitizeTraversal = false; // the client would refuse ".." itself
        await client.Connect(Ct);

        Assert.Equal("250", (await client.Execute("CWD /../../..", Ct)).Code);
        Assert.StartsWith("\"/\"", (await client.Execute("PWD", Ct)).Message);
        Assert.Equal("in"u8.ToArray(), await client.DownloadBytes("../../inside.txt", Ct));
    }

    [Fact]
    public async Task On_an_upload_only_path_STOR_works_and_RETR_gets_550()
    {
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("dropbox", u => u.Permissions = new() { ["/"] = FilePermissions.List, ["/incoming"] = FilePermissions.Upload });
        await host.StorageOf("dropbox").CreateDirectoryAsync("/incoming", Ct);
        await using var client = host.Client("dropbox");
        await client.Connect(Ct);

        Assert.Equal(FtpStatus.Success, await client.UploadBytes("secret"u8.ToArray(), "/incoming/drop.txt", FtpRemoteExists.NoCheck, token: Ct));
        Assert.Equal("secret", await host.StorageOf("dropbox").ReadAllTextAsync("/incoming/drop.txt"));

        var reply = await client.Execute("PASV", Ct);
        Assert.Equal("227", reply.Code);
        reply = await client.Execute("RETR /incoming/drop.txt", Ct);
        Assert.Equal("550", reply.Code);
        Assert.Contains(host.Events.FileEvents, e => e is { Type: FileEventType.Download, Status: FileEventStatus.Error });
        Assert.All(host.Events.FileEvents, e => Assert.Equal(ConnectionProtocols.Ftp, e.Protocol));
    }

    [Fact]
    public async Task An_upload_over_the_disk_quota_gets_552_and_leaves_no_file()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:Tls:Mode"] = "Optional" });
        host.AddUser("quota", u => u.DiskQuota = new DiskQuota { MaxSizeBytes = 64 * 1024 });
        await using (var client = host.Client("quota"))
        {
            await client.Connect(Ct);
            Assert.Equal(FtpStatus.Success, await client.UploadBytes(Data(32 * 1024), "/small.bin", token: Ct));
        }

        await using var raw = await host.RawAsync();
        await raw.ReadAsync();
        await raw.CommandAsync("USER quota");
        Assert.Equal(230, (await raw.CommandAsync("PASS " + FtpTestHost.Password)).Code);
        var (code, text) = await raw.CommandAsync("EPSV");
        Assert.Equal(229, code);
        var port = int.Parse(text.Split('|')[3], System.Globalization.CultureInfo.InvariantCulture);
        using (var data = new System.Net.Sockets.TcpClient())
        {
            await data.ConnectAsync(System.Net.IPAddress.Loopback, port, Ct);
            await raw.SendAsync("STOR /big.bin");
            Assert.Equal(150, (await raw.ReadAsync()).Code);
            try
            {
                await data.GetStream().WriteAsync(Data(128 * 1024), Ct);
            }
            catch (IOException)
            {
                // the server closed the data connection at the quota
            }
        }
        Assert.Equal(552, (await raw.ReadAsync()).Code);
        Assert.Null(await host.StorageOf("quota").StatAsync("/big.bin", true, Ct));
    }

    [Fact]
    [Trait("Category", "Slow")]
    public async Task The_bandwidth_limit_of_the_user_applies_to_the_data_connection()
    {
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("slow", u => u.Bandwidth = new BandwidthLimit { DownloadKiBPerSecond = 128 });
        await host.StorageOf("slow").WriteAllAsync("/f.bin", new byte[512 * 1024]);
        await using var client = host.Client("slow");
        await client.Connect(Ct);

        var watch = Stopwatch.StartNew();
        Assert.Equal(512 * 1024, (await client.DownloadBytes("/f.bin", Ct)).Length);
        Assert.InRange(watch.Elapsed.TotalSeconds, 2.5, 30);
    }

    [Fact]
    public async Task The_connection_is_in_the_registry_and_the_transfers_give_ftp_events()
    {
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("alice");
        await using var client = host.Client("alice");
        await client.Connect(Ct);

        var connection = Assert.Single(host.Connections.GetAll());
        Assert.Equal(ConnectionProtocols.Ftp, connection.Protocol);
        Assert.Equal("alice", connection.Username);
        await client.UploadBytes("hello"u8.ToArray(), "/a.txt", token: Ct);
        await client.DownloadBytes("/a.txt", Ct);

        var events = host.Events.FileEvents;
        Assert.Contains(events, e => e.Type is FileEventType.Upload or FileEventType.FirstUpload);
        Assert.Contains(events, e => e.Type == FileEventType.Download);
        Assert.All(events, e => Assert.Equal(ConnectionProtocols.Ftp, e.Protocol));
        Assert.NotNull(host.Repository.GetUser("alice")!.LastLoginAt);

        await client.Disconnect(Ct);
        await FtpSecurityTests.WaitUntilAsync(() => host.Connections.GetAll().Count == 0);
    }

    [Fact]
    public async Task Plain_ftp_works_when_tls_is_optional()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:Tls:Mode"] = "Optional" });
        host.AddUser("alice");
        await using (var plain = host.Client("alice", tls: false))
        {
            await plain.Connect(Ct);
            Assert.False(plain.IsEncrypted);
            await plain.UploadBytes("plain"u8.ToArray(), "/p.txt", token: Ct);
        }
        await using var secure = host.Client("alice");
        await secure.Connect(Ct);
        Assert.True(secure.IsEncrypted);
        Assert.Equal("plain"u8.ToArray(), await secure.DownloadBytes("/p.txt", Ct));
    }

    [Fact]
    public async Task Active_mode_works_when_it_is_allowed()
    {
        await using var host = await FtpTestHost.StartAsync(new Dictionary<string, string?> { ["Ftp:AllowActiveMode"] = "true" });
        host.AddUser("alice");
        await using var client = host.Client("alice", mode: FtpDataConnectionType.PORT);
        await client.Connect(Ct);

        await client.UploadBytes("active"u8.ToArray(), "/a.txt", token: Ct);
        Assert.Equal("active"u8.ToArray(), await client.DownloadBytes("/a.txt", Ct));
    }

    [Fact]
    public async Task Site_chmod_changes_the_mode_through_the_storage()
    {
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("alice");
        await host.StorageOf("alice").WriteAllAsync("/a.txt", "a");
        await using var client = host.Client("alice");
        await client.Connect(Ct);

        Assert.Equal("200", (await client.Execute("SITE CHMOD 600 /a.txt", Ct)).Code);
        Assert.Equal(0x180u, (await host.StorageOf("alice").StatAsync("/a.txt", true, Ct))!.Permissions);
        Assert.Equal("501", (await client.Execute("SITE CHMOD 9x9 /a.txt", Ct)).Code);
    }

    [Fact]
    public async Task Mlst_and_mlsd_give_the_standard_facts()
    {
        await using var host = await FtpTestHost.StartAsync();
        host.AddUser("alice");
        await host.StorageOf("alice").WriteAllAsync("/a.txt", "abc");
        await host.StorageOf("alice").CreateDirectoryAsync("/dir", Ct);
        await using var client = host.Client("alice");
        await client.Connect(Ct);

        var reply = await client.Execute("MLST /a.txt", Ct);
        Assert.Equal("250", reply.Code);
        Assert.Contains("type=file;size=3;", reply.InfoMessages);
        var listing = await client.GetListing("/", FtpListOption.Auto, Ct);
        Assert.Contains(listing, i => i is { Name: "dir", Type: FtpObjectType.Directory });
        Assert.Contains(listing, i => i is { Name: "a.txt", Size: 3 });
    }
}
