using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.WebUi;
using FreeSftpSharp.Tests.WebClient;
using FreeSftpSharp.Tests.Webhooks;
using FxSshSftpServer.WebClient;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Shares;
using SshServer.Webhooks;

namespace FreeSftpSharp.Tests.Shares;

/// <summary>
/// The share links (#70) over HTTP, anonymous: a read share (files and zip), the password, the expiry, the uses, the owner,
/// the containment of the paths, an upload share (the owner's folder over SFTP, the webhook, the quota), and the
/// management in the web client.
/// </summary>
[Collection(AdminUiCollection.Name)]
public sealed class ShareEndpointTests : IClassFixture<ShareFactory>, IClassFixture<SftpServerFixture>
{
    private readonly ShareFactory _factory;
    private readonly SftpServerFixture _sftp;

    public ShareEndpointTests(ShareFactory factory, SftpServerFixture sftp)
    {
        _factory = factory;
        _sftp = sftp;
        _factory.EnableShares(new ShareSettings { Enabled = true });
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static string NewName(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    /// <summary>A user with "/out" (two files and a sub folder), "/secret.txt" and an empty "/inbox".</summary>
    private string AddOwner(string name, DiskQuota? quota = null, Dictionary<string, FilePermissions>? permissions = null)
    {
        var root = _factory.AddUser(name, permissions, quota);
        Directory.CreateDirectory(Path.Combine(root, "out", "sub"));
        Directory.CreateDirectory(Path.Combine(root, "inbox"));
        File.WriteAllText(Path.Combine(root, "out", "a.txt"), "alpha");
        File.WriteAllText(Path.Combine(root, "out", "sub", "b.txt"), "beta");
        File.WriteAllText(Path.Combine(root, "secret.txt"), "secret");
        return root;
    }

    [Fact]
    public async Task A_read_share_of_a_folder_lets_an_anonymous_browser_download_each_file_and_the_zip()
    {
        var name = NewName("read");
        AddOwner(name);
        var share = await _factory.AddShareAsync(name, ShareScope.Read, ["/out"]);
        using var visitor = _factory.Visitor();

        var (status, html) = await visitor.OpenAsync(share.Id);
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Contains("id=\"share-roots\"", html);
        var (folderStatus, folder) = await visitor.OpenAsync(share.Id, "/out");
        Assert.Equal(HttpStatusCode.OK, folderStatus);
        Assert.Contains("a.txt", folder);
        Assert.Contains("sub", folder);
        Assert.Equal(WebClientSetup.ContentSecurityPolicy, (await visitor.Http.GetAsync("/shares/" + share.Id, Ct)).Headers.GetValues("Content-Security-Policy").Single());

        var file = await visitor.DownloadAsync(share.Id, "/out/sub/b.txt");
        Assert.Equal(HttpStatusCode.OK, file.StatusCode);
        Assert.Equal("beta", await file.Content.ReadAsStringAsync(Ct));
        Assert.Equal("attachment", file.Content.Headers.ContentDisposition!.DispositionType);
        Assert.Equal("nosniff", file.Headers.GetValues("X-Content-Type-Options").Single());

        var zip = await visitor.DownloadAsync(share.Id);
        Assert.Equal(HttpStatusCode.OK, zip.StatusCode);
        Assert.Equal("application/zip", zip.Content.Headers.ContentType!.MediaType);
        using (var archive = new ZipArchive(new MemoryStream(await zip.Content.ReadAsByteArrayAsync(Ct))))
            Assert.Equal(["out/a.txt", "out/sub/b.txt"], archive.Entries.Select(e => e.FullName).OrderBy(n => n, StringComparer.Ordinal));
        var folderZip = await visitor.DownloadAsync(share.Id, "/out/sub");
        using (var archive = new ZipArchive(new MemoryStream(await folderZip.Content.ReadAsByteArrayAsync(Ct))))
            Assert.Equal(["sub/b.txt"], archive.Entries.Select(e => e.FullName));

        var download = await _factory.Events.WaitForAsync<FileEvent>(e => e.Username == name && e.Type == FileEventType.Download && e.VirtualPath == "/out/sub/b.txt");
        Assert.Equal(ConnectionProtocols.HttpShare, download[0].Protocol);
        Assert.Equal(share.Id, download[0].Metadata!["shareId"]);
        var connection = Assert.Single(_factory.Services.GetRequiredService<IConnectionRegistry>().GetAll(), c => c.Username == name);
        Assert.Equal(ConnectionProtocols.HttpShare, connection.Protocol);
        Assert.Equal(3, (await _factory.Shares.GetAsync(share.Id, Ct))!.UsedCount);
    }

    [Theory]
    [InlineData("/secret.txt")]
    [InlineData("/out/../secret.txt")]
    [InlineData("/out/sub/../../secret.txt")]
    [InlineData("/outX/a.txt")]
    [InlineData("/")]
    [InlineData("/inbox")]
    public async Task Paths_outside_the_share_are_not_found(string path)
    {
        var name = NewName("contain");
        AddOwner(name);
        var share = await _factory.AddShareAsync(name, ShareScope.Read, ["/out"]);
        using var visitor = _factory.Visitor();

        Assert.Equal(HttpStatusCode.NotFound, (await visitor.DownloadAsync(share.Id, path)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await visitor.OpenAsync(share.Id, path)).Status);
        Assert.Equal(0, (await _factory.Shares.GetAsync(share.Id, Ct))!.UsedCount);
    }

    [Fact]
    public async Task A_share_with_a_password_refuses_without_it()
    {
        var name = NewName("pw");
        AddOwner(name);
        var share = await _factory.AddShareAsync(name, ShareScope.Read, ["/out"], password: true);
        using var visitor = _factory.Visitor();

        var (status, html) = await visitor.OpenAsync(share.Id);
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Contains("id=\"share-password-form\"", html);
        Assert.DoesNotContain("a.txt", html);
        Assert.Equal(HttpStatusCode.Unauthorized, (await visitor.DownloadAsync(share.Id, "/out/a.txt")).StatusCode);

        var wrong = await visitor.EnterPasswordAsync(share.Id, "not the password");
        Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
        Assert.Contains(FxSshSftpServer.Pages.Shares.IndexModel.WrongPasswordMessage, await wrong.Content.ReadAsStringAsync(Ct));
        Assert.Equal(HttpStatusCode.Unauthorized, (await visitor.DownloadAsync(share.Id, "/out/a.txt")).StatusCode);
        await _factory.Events.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.LoginFailed && e.Username == name && e.Protocol == ConnectionProtocols.HttpShare);

        var right = await visitor.EnterPasswordAsync(share.Id, ShareFactory.SharePassword);
        Assert.Equal(HttpStatusCode.Redirect, right.StatusCode);
        var cookie = Assert.Single(right.Headers.GetValues("Set-Cookie"), c => c.StartsWith(ShareAccess.CookieName + "=", StringComparison.Ordinal));
        Assert.Contains("path=/shares/" + share.Id, cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        var download = await visitor.DownloadAsync(share.Id, "/out/a.txt");
        Assert.Equal(HttpStatusCode.OK, download.StatusCode);
        Assert.Equal("alpha", await download.Content.ReadAsStringAsync(Ct));

        // The cookie of one share does not open another share with a password.
        var other = await _factory.AddShareAsync(name, ShareScope.Read, ["/out"], password: true);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/shares/" + other.Id + "/download?path=%2Fout%2Fa.txt");
        request.Headers.Add("Cookie", cookie.Split(';')[0]);
        using var plain = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });
        Assert.Equal(HttpStatusCode.Unauthorized, (await plain.SendAsync(request, Ct)).StatusCode);
    }

    [Fact]
    public async Task A_share_stops_working_after_ExpiresAt()
    {
        var name = NewName("exp");
        AddOwner(name);
        var expired = await _factory.AddShareAsync(name, ShareScope.Read, ["/out"], s => s.ExpiresAt = DateTime.UtcNow.AddMinutes(-1));
        var valid = await _factory.AddShareAsync(name, ShareScope.Read, ["/out"], s => s.ExpiresAt = DateTime.UtcNow.AddHours(1));
        using var visitor = _factory.Visitor();

        Assert.Equal(HttpStatusCode.NotFound, (await visitor.OpenAsync(expired.Id)).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await visitor.DownloadAsync(expired.Id, "/out/a.txt")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await visitor.DownloadAsync(valid.Id, "/out/a.txt")).StatusCode);
    }

    [Fact]
    public async Task A_share_stops_working_after_MaxUses()
    {
        var name = NewName("uses");
        AddOwner(name);
        var share = await _factory.AddShareAsync(name, ShareScope.Read, ["/out"], s => s.MaxUses = 2);
        using var visitor = _factory.Visitor();

        Assert.Equal(HttpStatusCode.OK, (await visitor.DownloadAsync(share.Id, "/out/a.txt")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await visitor.DownloadAsync(share.Id)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await visitor.DownloadAsync(share.Id, "/out/a.txt")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await visitor.OpenAsync(share.Id)).Status);
    }

    [Fact]
    public async Task A_share_whose_owner_is_disabled_or_removed_is_not_found()
    {
        var name = NewName("owner");
        AddOwner(name);
        var share = await _factory.AddShareAsync(name, ShareScope.Read, ["/out"]);
        using var visitor = _factory.Visitor();
        Assert.Equal(HttpStatusCode.OK, (await visitor.OpenAsync(share.Id)).Status);

        var user = _factory.Repository.GetUser(name);
        user.Status = UserStatus.Disabled;
        Assert.True(_factory.Repository.UpdateUser(user));
        Assert.Equal(HttpStatusCode.NotFound, (await visitor.OpenAsync(share.Id)).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await visitor.DownloadAsync(share.Id, "/out/a.txt")).StatusCode);

        // A new user with the same name does not get the shares of the old one.
        Assert.True(_factory.Repository.RemoveUser(name));
        AddOwner(name);
        Assert.Equal(HttpStatusCode.NotFound, (await visitor.OpenAsync(share.Id)).Status);
    }

    [Fact]
    public async Task Unknown_and_malformed_ids_and_a_server_without_sharing_answer_404()
    {
        var name = NewName("ids");
        AddOwner(name);
        var share = await _factory.AddShareAsync(name, ShareScope.Read, ["/out"]);
        using var visitor = _factory.Visitor();

        Assert.Equal(HttpStatusCode.NotFound, (await visitor.OpenAsync(ShareId.New())).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await visitor.OpenAsync("not-an-id")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await visitor.DownloadAsync("AAAAAAAAAAAAAAAAAAAAAAAAAA!", "/out/a.txt")).StatusCode);

        _factory.EnableShares(new ShareSettings { Enabled = false });
        try
        {
            Assert.Equal(HttpStatusCode.NotFound, (await visitor.OpenAsync(share.Id)).Status);
            Assert.Equal(HttpStatusCode.NotFound, (await visitor.DownloadAsync(share.Id, "/out/a.txt")).StatusCode);
        }
        finally
        {
            _factory.EnableShares(new ShareSettings { Enabled = true });
        }
        Assert.Equal(HttpStatusCode.OK, (await visitor.OpenAsync(share.Id)).Status);
    }

    [Fact]
    public async Task An_upload_share_puts_the_file_into_the_owners_folder_with_a_webhook_and_it_is_visible_over_SFTP()
    {
        var name = NewName("inbox");
        var root = AddOwner(name);
        await using var receiver = await WebhookReceiver.StartAsync();
        var webhook = await _factory.Services.GetRequiredService<WebhookAdministrationService>().SaveAsync(AdminActor.System, new WebhookInput
        {
            Name = NewName("hook"),
            Url = receiver.Url("/upload"),
            EventTypes = ["File.Upload"],
            Users = [name],
        }, Ct);
        Assert.True(webhook.Succeeded, string.Join(" ", webhook.Errors));
        var share = await _factory.AddShareAsync(name, ShareScope.Write, ["/inbox"]);
        using var visitor = _factory.Visitor();

        var (status, html) = await visitor.OpenAsync(share.Id);
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Contains("id=\"upload-input\"", html);
        Assert.Contains($"data-api=\"/shares/{share.Id}\"", html);
        var data = Encoding.UTF8.GetBytes("report from a partner");
        var chunk = await visitor.PostChunkAsync(share.Id, "/inbox/report.csv", Guid.NewGuid().ToString("N"), data, 0, data.Length);
        Assert.True(chunk.IsSuccessStatusCode, await chunk.Content.ReadAsStringAsync(Ct));
        Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(root, "inbox", "report.csv"), Ct));

        // The webhook of the owner fires with the protocol of the share.
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!receiver.Requests.Any() && DateTime.UtcNow < deadline)
            await Task.Delay(50, Ct);
        var sent = Assert.Single(receiver.Requests);
        Assert.Equal("HTTPShare", sent.Json.GetProperty("protocol").GetString());
        Assert.Equal("/inbox/report.csv", sent.Json.GetProperty("virtual_path").GetString());
        Assert.Equal(share.Id, sent.Json.GetProperty("metadata").GetProperty("shareId").GetString());

        // The owner sees the file over SFTP (SSH.NET), in the same folder.
        Assert.True(_sftp.Repository.AddUser(new User
        {
            Username = name,
            HashedPassword = TestCredentials.HashPassword(_sftp.Password),
            UserRootDirectory = root,
            WhitelistedIps = [],
        }));
        using var sftp = _sftp.CreateClient(username: name);
        sftp.Connect();
        Assert.Contains("report.csv", sftp.ListDirectory("/inbox").Select(f => f.Name));
        Assert.Equal("report from a partner", sftp.ReadAllText("/inbox/report.csv"));
    }

    [Fact]
    public async Task An_upload_share_never_overwrites_never_leaves_its_folder_and_cannot_download()
    {
        var name = NewName("inbox2");
        var root = AddOwner(name);
        File.WriteAllText(Path.Combine(root, "inbox", "exists.txt"), "old");
        var share = await _factory.AddShareAsync(name, ShareScope.Write, ["/inbox"]);
        using var visitor = _factory.Visitor();
        await visitor.OpenAsync(share.Id);
        var data = Encoding.UTF8.GetBytes("new");

        var overwrite = await visitor.PostChunkAsync(share.Id, "/inbox/exists.txt", Guid.NewGuid().ToString("N"), data, 0, data.Length, overwrite: true);
        Assert.Equal(HttpStatusCode.Conflict, overwrite.StatusCode);
        Assert.Equal("old", File.ReadAllText(Path.Combine(root, "inbox", "exists.txt")));

        foreach (var path in new[] { "/out/x.txt", "/inbox/../x.txt", "/x.txt", "/inbox/..", "/inbox/sub/x.txt" })
        {
            var outside = await visitor.PostChunkAsync(share.Id, path, Guid.NewGuid().ToString("N"), data, 0, data.Length);
            Assert.True(outside.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.BadRequest, $"{path}: {outside.StatusCode}");
        }
        Assert.False(File.Exists(Path.Combine(root, "x.txt")));
        Assert.False(File.Exists(Path.Combine(root, "out", "x.txt")));

        Assert.Equal(HttpStatusCode.Forbidden, (await visitor.DownloadAsync(share.Id, "/inbox/exists.txt")).StatusCode);
        var (_, html) = await visitor.OpenAsync(share.Id);
        Assert.DoesNotContain("exists.txt", html); // an inbox does not list its content

        // Without the antiforgery token of the page, an upload is refused.
        using var stranger = _factory.Visitor();
        var csrf = await stranger.PostChunkAsync(share.Id, "/inbox/csrf.txt", Guid.NewGuid().ToString("N"), data, 0, data.Length);
        Assert.Equal(HttpStatusCode.BadRequest, csrf.StatusCode);
        Assert.False(File.Exists(Path.Combine(root, "inbox", "csrf.txt")));
    }

    [Fact]
    public async Task A_read_share_refuses_uploads()
    {
        var name = NewName("ro");
        var root = AddOwner(name);
        var share = await _factory.AddShareAsync(name, ShareScope.Read, ["/out"]);
        using var visitor = _factory.Visitor();
        var writable = await _factory.AddShareAsync(name, ShareScope.Write, ["/inbox"]);
        await visitor.OpenAsync(writable.Id); // an antiforgery token

        var upload = await visitor.PostChunkAsync(share.Id, "/out/new.txt", Guid.NewGuid().ToString("N"), [1, 2, 3], 0, 3);

        Assert.Equal(HttpStatusCode.Forbidden, upload.StatusCode);
        Assert.False(File.Exists(Path.Combine(root, "out", "new.txt")));
    }

    [Fact]
    public async Task An_upload_share_refuses_when_the_owners_quota_is_full()
    {
        var name = NewName("quota");
        var root = AddOwner(name, quota: new DiskQuota { MaxSizeBytes = 1000 });
        var share = await _factory.AddShareAsync(name, ShareScope.Write, ["/inbox"]);
        using var visitor = _factory.Visitor();
        await visitor.OpenAsync(share.Id);

        var check = await visitor.CheckAsync(share.Id, "/inbox/large.bin", 5000);
        Assert.Equal(HttpStatusCode.OK, check.StatusCode);
        Assert.Contains("Not enough space", await check.Content.ReadAsStringAsync(Ct));
        var chunk = await visitor.PostChunkAsync(share.Id, "/inbox/large.bin", Guid.NewGuid().ToString("N"), new byte[2500], 0, 5000);

        Assert.Equal(HttpStatusCode.InsufficientStorage, chunk.StatusCode);
        Assert.False(File.Exists(Path.Combine(root, "inbox", "large.bin")));
    }

    [Fact]
    public async Task The_owner_creates_lists_and_revokes_a_share_in_the_web_client()
    {
        var name = NewName("manage");
        AddOwner(name);
        using var browser = await _factory.LogInAsync(name);
        var page = await browser.Http.GetAsync("/client/shares?path=%2Fout", Ct);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var html = await page.Content.ReadAsStringAsync(Ct);

        var create = await browser.Http.PostAsync("/client/shares?handler=Create", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Name"] = "Reports",
            ["PathsText"] = "/out",
            ["Scope"] = "Read",
            ["MaxUses"] = "0",
            ["__RequestVerificationToken"] = ClientBrowser.FormToken(html),
        }), Ct);
        var created = await create.Content.ReadAsStringAsync(Ct);
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        Assert.Contains("id=\"share-created\"", created);
        var share = Assert.Single(await _factory.Shares.ListAsync(_factory.Repository.GetUser(name).Id, Ct));
        Assert.Equal(["/out"], share.Paths);
        Assert.Contains("/shares/" + share.Id, created);
        using var visitor = _factory.Visitor();
        Assert.Equal(HttpStatusCode.OK, (await visitor.DownloadAsync(share.Id, "/out/a.txt")).StatusCode);

        // A path that does not exist, and a missing password where the server needs one, are refused.
        _factory.EnableShares(new ShareSettings { Enabled = true, RequirePassword = true, MaxLifetimeDays = 7 });
        try
        {
            var refused = await browser.Http.PostAsync("/client/shares?handler=Create", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["Name"] = "Bad",
                ["PathsText"] = "/missing",
                ["Scope"] = "Read",
                ["ExpiresAt"] = DateTime.UtcNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm"),
                ["__RequestVerificationToken"] = ClientBrowser.FormToken(created),
            }), Ct);
            var errors = await refused.Content.ReadAsStringAsync(Ct);
            Assert.Contains("id=\"share-errors\"", errors);
            Assert.Contains("/missing does not exist", errors);
            Assert.Contains("needs one", errors);
            Assert.Contains("at most 7 days", errors);
        }
        finally
        {
            _factory.EnableShares(new ShareSettings { Enabled = true });
        }

        var revoke = await browser.Http.PostAsync("/client/shares?handler=Revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["id"] = share.Id,
            ["__RequestVerificationToken"] = ClientBrowser.FormToken(created),
        }), Ct);
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        Assert.Empty(await _factory.Shares.ListAsync(_factory.Repository.GetUser(name).Id, Ct));
        Assert.Equal(HttpStatusCode.NotFound, (await visitor.DownloadAsync(share.Id, "/out/a.txt")).StatusCode);
    }

    [Fact]
    public async Task A_user_cannot_revoke_the_share_of_another_user()
    {
        var owner = NewName("own");
        AddOwner(owner);
        var share = await _factory.AddShareAsync(owner, ShareScope.Read, ["/out"]);
        var other = NewName("other");
        AddOwner(other);
        using var browser = await _factory.LogInAsync(other);
        var html = await (await browser.Http.GetAsync("/client/shares", Ct)).Content.ReadAsStringAsync(Ct);
        Assert.DoesNotContain(share.Id, html);

        await browser.Http.PostAsync("/client/shares?handler=Revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["id"] = share.Id,
            ["__RequestVerificationToken"] = ClientBrowser.FormToken(html),
        }), Ct);

        Assert.NotNull(await _factory.Shares.GetAsync(share.Id, Ct));
    }
}
