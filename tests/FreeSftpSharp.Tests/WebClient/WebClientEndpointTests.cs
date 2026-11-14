using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using FreeSftpSharp.Tests.WebUi;
using FxSshSftpServer.WebClient;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Quotas;

namespace FreeSftpSharp.Tests.WebClient;

/// <summary>The web client (#69) over HTTP: login, cookie separation, the file endpoints through the decorator chain.</summary>
[Collection(AdminUiCollection.Name)]
public sealed class WebClientEndpointTests : IClassFixture<WebClientFactory>
{
    private readonly WebClientFactory _factory;

    public WebClientEndpointTests(WebClientFactory factory)
    {
        _factory = factory;
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static string NewName(string prefix) => prefix + Guid.NewGuid().ToString("N")[..8];

    [Fact]
    public async Task Login_opens_the_file_browser_and_registers_an_HTTP_session()
    {
        var name = NewName("login");
        _factory.AddUser(name);
        using var browser = await _factory.LogInAsync(name);

        var (status, html) = await browser.OpenFilesAsync();

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Contains("id=\"file-browser\"", html);
        var connection = Assert.Single(_factory.Services.GetRequiredService<IConnectionRegistry>().GetAll(), c => c.Username == name);
        Assert.Equal(ConnectionProtocols.Http, connection.Protocol);
        await _factory.Events.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.LoginOk && e.Username == name && e.Protocol == "HTTP");
    }

    [Fact]
    public async Task Wrong_password_is_refused_with_an_event()
    {
        var name = NewName("wrong");
        _factory.AddUser(name);
        using var browser = new ClientBrowser(_factory.CreateBrowser());

        var response = await browser.LogInAsync(name, "not the password");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(FxSshSftpServer.Pages.Client.LoginModel.InvalidCredentialsMessage, await response.Content.ReadAsStringAsync(Ct));
        Assert.Equal(HttpStatusCode.Redirect, (await browser.Http.GetAsync("/client", Ct)).StatusCode);
        await _factory.Events.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.LoginFailed && e.Username == name && e.Protocol == "HTTP");
    }

    [Fact]
    public async Task A_user_without_the_web_protocol_is_refused()
    {
        var name = NewName("noweb");
        _factory.AddUser(name, change: u => u.AllowedProtocols = SshServer.Interfaces.Authentication.UserProtocols.Sftp);
        using var browser = new ClientBrowser(_factory.CreateBrowser());

        var response = await browser.LogInAsync(name, WebClientFactory.UserPassword);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await browser.Http.GetAsync("/client", Ct)).StatusCode);
    }

    [Fact]
    public async Task An_admin_cookie_does_not_open_the_client()
    {
        using var browser = _factory.CreateBrowser();
        var login = await AdminUiAuthenticationTests.LogInAsync(browser, AdminUiFactory.AdminUserName, AdminUiFactory.AdminPassword);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/", Ct)).StatusCode); // the admin login works

        var page = await browser.GetAsync("/client", Ct);
        Assert.Equal(HttpStatusCode.Redirect, page.StatusCode);
        Assert.Equal("/client/login", page.Headers.Location!.AbsolutePath, ignoreCase: true);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/client/api/list?path=/", Ct)).StatusCode);
    }

    [Fact]
    public async Task A_client_cookie_does_not_open_the_admin_UI()
    {
        var name = NewName("sep");
        _factory.AddUser(name);
        using var browser = new ClientBrowser(_factory.CreateBrowser());
        var login = await browser.LogInAsync(name, WebClientFactory.UserPassword);
        var cookie = Assert.Single(login.Headers.GetValues("Set-Cookie"), c => c.StartsWith(ClientAuth.CookieName + "=", StringComparison.Ordinal));
        Assert.Contains("path=/client", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);

        // The browser would not send the cookie to "/"; send it anyway, as a crafted request would.
        using var request = new HttpRequestMessage(HttpMethod.Get, "/");
        request.Headers.Add("Cookie", cookie.Split(';')[0]);
        using var plain = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });
        var admin = await plain.SendAsync(request, Ct);

        Assert.Equal(HttpStatusCode.Redirect, admin.StatusCode);
        Assert.Equal("/Login", admin.Headers.Location!.AbsolutePath);
    }

    [Fact]
    public async Task Upload_in_chunks_and_download_are_byte_identical_and_audited_with_protocol_HTTP()
    {
        var name = NewName("round");
        var root = _factory.AddUser(name);
        using var browser = await _factory.LogInAsync(name);
        var data = new byte[3 * 1024 * 1024 + 12345];
        Random.Shared.NextBytes(data);

        await browser.UploadAsync("/big.bin", data, chunkSize: 1024 * 1024);

        Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(root, "big.bin"), Ct));
        var download = await browser.Http.GetAsync("/client/api/download?path=%2Fbig.bin", Ct);
        Assert.Equal(HttpStatusCode.OK, download.StatusCode);
        Assert.Equal(data.Length, download.Content.Headers.ContentLength);
        Assert.Equal("attachment", download.Content.Headers.ContentDisposition!.DispositionType);
        Assert.Equal("application/octet-stream", download.Content.Headers.ContentType!.MediaType);
        Assert.Equal("nosniff", download.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal(data, await download.Content.ReadAsByteArrayAsync(Ct));

        using var ranged = new HttpRequestMessage(HttpMethod.Get, "/client/api/download?path=%2Fbig.bin");
        ranged.Headers.Range = new RangeHeaderValue(1000, 1999);
        var part = await browser.Http.SendAsync(ranged, Ct);
        Assert.Equal(HttpStatusCode.PartialContent, part.StatusCode);
        Assert.Equal(data.AsSpan(1000, 1000).ToArray(), await part.Content.ReadAsByteArrayAsync(Ct));

        var delete = await browser.PostJsonAsync("/client/api/delete", new { paths = new[] { "/big.bin" } });
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
        Assert.False(File.Exists(Path.Combine(root, "big.bin")));

        await _factory.Events.WaitForAsync<FileEvent>(e => e.Username == name && e.Type == FileEventType.FirstUpload && e.Protocol == "HTTP");
        await _factory.Events.WaitForAsync<FileEvent>(e => e.Username == name && e.Type == FileEventType.Download && e.Protocol == "HTTP");
        await _factory.Events.WaitForAsync<FileEvent>(e => e.Username == name && e.Type == FileEventType.Delete && e.Protocol == "HTTP");
    }

    [Fact]
    public async Task A_chunk_out_of_order_is_refused_with_the_offset_to_resume_at()
    {
        var name = NewName("resume");
        var root = _factory.AddUser(name);
        using var browser = await _factory.LogInAsync(name);
        var data = new byte[300_000];
        Random.Shared.NextBytes(data);
        var id = Guid.NewGuid().ToString("N");

        Assert.True((await browser.PostChunkAsync("/r.bin", id, data[..100_000], 0, data.Length)).IsSuccessStatusCode);
        var skipped = await browser.PostChunkAsync("/r.bin", id, data[200_000..], 200_000, data.Length);
        Assert.Equal(HttpStatusCode.Conflict, skipped.StatusCode);
        var status = await browser.Http.GetFromJsonAsync<UploadStatus>("/client/api/upload?path=%2Fr.bin&id=" + id, Ct);
        Assert.Equal(100_000, status!.Offset);

        Assert.True((await browser.PostChunkAsync("/r.bin", id, data[100_000..200_000], 100_000, data.Length)).IsSuccessStatusCode);
        Assert.True((await browser.PostChunkAsync("/r.bin", id, data[200_000..], 200_000, data.Length)).IsSuccessStatusCode);
        Assert.Equal(data, await File.ReadAllBytesAsync(Path.Combine(root, "r.bin"), Ct));
    }

    private sealed record UploadStatus(long Offset, bool Known);

    [Fact]
    public async Task Upload_only_folder_shows_the_upload_button_and_refuses_a_crafted_download_with_403()
    {
        var name = NewName("perm");
        var root = _factory.AddUser(name, new Dictionary<string, FilePermissions>
        {
            ["/"] = FilePermissions.All,
            ["/incoming"] = FilePermissions.Upload,
        });
        Directory.CreateDirectory(Path.Combine(root, "incoming"));
        await File.WriteAllTextAsync(Path.Combine(root, "incoming", "secret.txt"), "secret", Ct);
        using var browser = await _factory.LogInAsync(name);

        var (status, html) = await browser.OpenFilesAsync("/incoming");

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Contains("id=\"upload-button\"", html);
        Assert.DoesNotContain("action-download", html);
        Assert.DoesNotContain("action-delete", html);
        Assert.DoesNotContain("id=\"delete-selected\"", html);
        Assert.DoesNotContain("id=\"zip-selected\"", html);
        Assert.DoesNotContain("secret.txt", html); // no List either

        Assert.Equal(HttpStatusCode.Forbidden, (await browser.Http.GetAsync("/client/api/download?path=%2Fincoming%2Fsecret.txt", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.PostJsonAsync("/client/api/delete", new { paths = new[] { "/incoming/secret.txt" } })).StatusCode);
        Assert.True(File.Exists(Path.Combine(root, "incoming", "secret.txt")));
        // The permitted action works.
        await browser.UploadAsync("/incoming/new.txt", "hello"u8.ToArray());
        Assert.True(File.Exists(Path.Combine(root, "incoming", "new.txt")));
        // The refused download is in the audit log too (the events are outside the permissions).
        await _factory.Events.WaitForAsync<FileEvent>(e => e.Username == name && e.Status == FileEventStatus.Error && e.Protocol == "HTTP"
                                                           && e.VirtualPath == "/incoming/secret.txt");
    }

    [Fact]
    public async Task Over_quota_the_upload_is_refused_before_the_first_byte()
    {
        var name = NewName("quota");
        var root = _factory.AddUser(name, quota: new DiskQuota { MaxSizeBytes = 1000 });
        using var browser = await _factory.LogInAsync(name);
        var (pageStatus, pageHtml) = await browser.OpenFilesAsync();
        Assert.True(pageStatus == HttpStatusCode.OK, pageHtml);

        var check = await browser.PostJsonAsync("/client/api/upload/check", new { files = new[] { new { path = "/large.bin", size = 5000 } } });
        Assert.Equal(HttpStatusCode.OK, check.StatusCode);
        var result = Assert.Single((await check.Content.ReadFromJsonAsync<CheckResult[]>(Ct))!);
        Assert.Contains("Not enough space", result.Problem);

        var chunk = await browser.PostChunkAsync("/large.bin", Guid.NewGuid().ToString("N"), new byte[2500], 0, 5000);
        Assert.Equal(HttpStatusCode.InsufficientStorage, chunk.StatusCode);
        Assert.Contains("Not enough space", await chunk.Content.ReadAsStringAsync(Ct));
        Assert.False(File.Exists(Path.Combine(root, "large.bin")));
    }

    private sealed record CheckResult(string Path, bool Exists, string? Problem);

    [Fact]
    public async Task A_request_without_the_antiforgery_token_is_refused()
    {
        var name = NewName("csrf");
        var root = _factory.AddUser(name);
        using var browser = await _factory.LogInAsync(name);

        var response = await browser.Http.PostAsync("/client/api/mkdir", JsonContent.Create(new { path = "/evil" }), Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(Directory.Exists(Path.Combine(root, "evil")));
        Assert.Equal(HttpStatusCode.OK, (await browser.PostJsonAsync("/client/api/mkdir", new { path = "/good" })).StatusCode);
        Assert.True(Directory.Exists(Path.Combine(root, "good")));
    }

    [Fact]
    public async Task Rename_and_folder_zip_download()
    {
        var name = NewName("zip");
        var root = _factory.AddUser(name);
        Directory.CreateDirectory(Path.Combine(root, "docs", "sub"));
        await File.WriteAllTextAsync(Path.Combine(root, "docs", "a.txt"), "alpha", Ct);
        await File.WriteAllTextAsync(Path.Combine(root, "docs", "sub", "b.txt"), "beta", Ct);
        using var browser = await _factory.LogInAsync(name);

        Assert.Equal(HttpStatusCode.OK, (await browser.PostJsonAsync("/client/api/rename", new { path = "/docs/a.txt", newName = "c.txt" })).StatusCode);
        Assert.True(File.Exists(Path.Combine(root, "docs", "c.txt")));

        var zip = await browser.Http.PostAsync("/client/api/zip", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["path"] = "/docs",
            ["__RequestVerificationToken"] = await browser.RequireTokenAsync(),
        }), Ct);
        Assert.Equal(HttpStatusCode.OK, zip.StatusCode);
        Assert.Equal("attachment", zip.Content.Headers.ContentDisposition!.DispositionType);
        using var archive = new ZipArchive(new MemoryStream(await zip.Content.ReadAsByteArrayAsync(Ct)));
        var entries = archive.Entries.ToDictionary(e => e.FullName, e => new StreamReader(e.Open()).ReadToEnd());
        Assert.Equal("alpha", entries["docs/c.txt"]);
        Assert.Equal("beta", entries["docs/sub/b.txt"]);
    }

    [Fact]
    public async Task Pages_have_a_strict_content_security_policy()
    {
        using var browser = _factory.CreateBrowser();

        var response = await browser.GetAsync("/client/login", Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var csp = response.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("script-src 'self'", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
    }

    [Fact]
    public async Task Logout_ends_the_session()
    {
        var name = NewName("logout");
        _factory.AddUser(name);
        using var browser = await _factory.LogInAsync(name);
        var (_, html) = await browser.OpenFilesAsync();

        var logout = await browser.Http.PostAsync("/client/logout", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = ClientBrowser.FormToken(html),
        }), Ct);

        Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
        Assert.DoesNotContain(_factory.Services.GetRequiredService<IConnectionRegistry>().GetAll(), c => c.Username == name);
        await _factory.Events.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.Logout && e.Username == name && e.Protocol == "HTTP");
    }

    [Fact]
    public async Task A_user_with_TOTP_logs_in_with_the_code()
    {
        var name = NewName("totp");
        _factory.AddUser(name);
        var service = _factory.Services.GetRequiredService<SshServer.TwoFactor.TwoFactorService>();
        var time = _factory.Services.GetRequiredService<TimeProvider>();
        var (secret, _) = await FreeSftpSharp.Tests.Infrastructure.TwoFactorTestKit.EnrolAsync(service,
            SshServer.Interfaces.TwoFactor.TwoFactorSubject.ForUser(_factory.Repository.GetUser(name)), time);
        using var browser = new ClientBrowser(_factory.CreateBrowser());

        var login = await browser.LogInAsync(name, WebClientFactory.UserPassword);
        Assert.Equal("/client/logincode", login.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.Redirect, (await browser.Http.GetAsync("/client", Ct)).StatusCode); // no access yet

        var page = await browser.Http.GetAsync("/client/logincode", Ct);
        var code = await browser.Http.PostAsync("/client/logincode", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Code"] = FreeSftpSharp.Tests.Infrastructure.TwoFactorTestKit.Code(secret, time.GetUtcNow()),
            ["__RequestVerificationToken"] = ClientBrowser.FormToken(await page.Content.ReadAsStringAsync(Ct)),
        }), Ct);

        Assert.Equal(HttpStatusCode.Redirect, code.StatusCode);
        Assert.Equal("/client", code.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await browser.OpenFilesAsync()).Status);
        await _factory.Events.WaitForAsync<AuthEvent>(e => e.Type == AuthEventType.LoginOk && e.Username == name && e.Method == "password,totp");
    }

    [Fact]
    public async Task The_account_page_adds_and_removes_a_public_key()
    {
        var name = NewName("keys");
        _factory.AddUser(name);
        using var browser = await _factory.LogInAsync(name);
        var page = await browser.Http.GetAsync("/client/account", Ct);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var html = await page.Content.ReadAsStringAsync(Ct);

        var add = await browser.Http.PostAsync("/client/account?handler=AddKeys", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["KeysText"] = FreeSftpSharp.Tests.Infrastructure.TestUserKeys.Ed25519().AuthorizedKeysLine,
            ["__RequestVerificationToken"] = ClientBrowser.FormToken(html),
        }), Ct);

        Assert.Equal(HttpStatusCode.OK, add.StatusCode);
        var key = Assert.Single(_factory.Repository.GetUser(name).PublicKeys!);
        Assert.Equal(SshServer.Interfaces.Authentication.PublicKeySource.SelfService, key.Source);
        var remove = await browser.Http.PostAsync("/client/account?handler=RemoveKey", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["key"] = key.KeyBase64,
            ["__RequestVerificationToken"] = ClientBrowser.FormToken(await add.Content.ReadAsStringAsync(Ct)),
        }), Ct);
        Assert.Equal(HttpStatusCode.OK, remove.StatusCode);
        Assert.Empty(_factory.Repository.GetUser(name).PublicKeys!);
    }

    [Fact]
    public async Task An_expired_password_must_be_changed_first()
    {
        var name = NewName("expired");
        _factory.AddUser(name, change: u => u.PasswordChangedAt = DateTime.UtcNow.AddDays(-400));
        var settings = _factory.Repository.ServerSettings;
        settings.PasswordMaxAgeDays = 90;
        try
        {
            using var browser = new ClientBrowser(_factory.CreateBrowser());
            var login = await browser.LogInAsync(name, WebClientFactory.UserPassword);
            Assert.Equal("/client/changepassword", login.Headers.Location!.OriginalString);

            var files = await browser.Http.GetAsync("/client", Ct);
            Assert.Equal(HttpStatusCode.Redirect, files.StatusCode);
            Assert.Equal("/client/changepassword", files.Headers.Location!.OriginalString);

            var page = await browser.Http.GetAsync("/client/changepassword", Ct);
            var change = await browser.Http.PostAsync("/client/changepassword", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["CurrentPassword"] = WebClientFactory.UserPassword,
                ["NewPassword"] = "A-New-Password-7",
                ["RepeatPassword"] = "A-New-Password-7",
                ["__RequestVerificationToken"] = ClientBrowser.FormToken(await page.Content.ReadAsStringAsync(Ct)),
            }), Ct);
            Assert.Equal(HttpStatusCode.Redirect, change.StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await browser.OpenFilesAsync()).Status);
            Assert.True(SshServer.Interfaces.Security.PasswordHasher.Verify("A-New-Password-7", _factory.Repository.GetUser(name).HashedPassword!));
        }
        finally
        {
            settings.PasswordMaxAgeDays = 0;
        }
    }
}

/// <summary>Without <c>WebClient:Enabled</c> the client area does not exist.</summary>
[Collection(AdminUiCollection.Name)]
public sealed class WebClientDisabledTests : IClassFixture<AdminUiFactory>
{
    private readonly AdminUiFactory _factory;

    public WebClientDisabledTests(AdminUiFactory factory)
    {
        _factory = factory;
    }

    [Theory]
    [InlineData("/client")]
    [InlineData("/client/login")]
    [InlineData("/client/api/list?path=/")]
    public async Task Every_client_path_answers_404(string path)
    {
        using var browser = _factory.CreateBrowser();

        var response = await browser.GetAsync(path, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
