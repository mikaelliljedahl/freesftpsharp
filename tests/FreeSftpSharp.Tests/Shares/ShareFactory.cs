using FreeSftpSharp.Tests.Settings.Providers;
using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using FreeSftpSharp.Tests.WebClient;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Shares;
using SshServer.Interfaces.Webhooks;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.Webhooks;

namespace FreeSftpSharp.Tests.Shares;

/// <summary>
/// The web client host with the share links (#70) on, and the webhooks in a SQLite file of their own (so an upload of a
/// share fires a real webhook). <see cref="EnableShares"/> turns <c>ServerSettings.Shares</c> on.
/// </summary>
public sealed partial class ShareFactory : WebClientFactory
{
    public const string SharePassword = "Share-Password-7";

    private static readonly string SharePasswordHash = PasswordHasher.Hash(SharePassword, PasswordHasher.MinimumIterations);

    private readonly TestDatabase _database = TestDatabase.CreateDefault();
    private readonly DbContextOptions<SettingsDbContext> _db;

    public ShareFactory()
    {
        _db = _database.Options;
        _ = new SqlSettingsRepository(_db, createHostKey: () => TestCredentials.HostKey); // creates and migrates the database
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("Webhooks:AllowInsecureWebhooks", "true");
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IWebhookStore>();
            services.AddSingleton<IWebhookStore>(new SqlWebhookStore(_db));
        });
    }

    public IShareStore Shares => Services.GetRequiredService<IShareStore>();

    /// <summary>Sets <c>ServerSettings.Shares</c>; null turns sharing off.</summary>
    public void EnableShares(ShareSettings? settings)
    {
        var server = Repository.ServerSettings;
        server.Shares = settings;
        Repository.UpdateServerSettings(server);
    }

    /// <summary>Adds a share of <paramref name="owner"/> (an existing user) to the store and turns sharing on.</summary>
    public async Task<Share> AddShareAsync(string owner, ShareScope scope, string[] paths, Action<Share>? change = null, bool password = false)
    {
        if (Repository.ServerSettings.Shares is not { Enabled: true })
            EnableShares(new ShareSettings { Enabled = true });
        var user = Repository.GetUser(owner);
        var share = new Share
        {
            Id = ShareId.New(),
            UserId = user.Id,
            Username = user.Username,
            Name = "Share of " + owner,
            Paths = paths.ToList(),
            Scope = scope,
            PasswordHash = password ? SharePasswordHash : null,
            CreatedAt = DateTime.UtcNow,
        };
        change?.Invoke(share);
        await Shares.AddAsync(share, TestContext.Current.CancellationToken);
        return share;
    }

    /// <summary>A browser without a login (a visitor of a link).</summary>
    public ShareVisitor Visitor() => new(CreateBrowser());

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        _database.Dispose();
    }
}

/// <summary>An anonymous browser on a share link: the landing page (and its antiforgery token), the password, the endpoints.</summary>
public sealed partial class ShareVisitor : IDisposable
{
    public ShareVisitor(HttpClient http)
    {
        Http = http;
    }

    public HttpClient Http { get; }

    public string? Token { get; private set; }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public async Task<(HttpStatusCode Status, string Html)> OpenAsync(string id, string? path = null)
    {
        var response = await Http.GetAsync("/shares/" + id + (path == null ? "" : "?path=" + Uri.EscapeDataString(path)), Ct);
        var html = await response.Content.ReadAsStringAsync(Ct);
        var data = DataTokenRegex().Match(html);
        if (data.Success)
            Token = WebUtility.HtmlDecode(data.Groups[1].Value);
        else if (ClientBrowser.FormToken(html) is { Length: > 0 } form)
            Token = form;
        return (response.StatusCode, html);
    }

    public async Task<HttpResponseMessage> EnterPasswordAsync(string id, string password)
    {
        var (_, html) = await OpenAsync(id);
        return await Http.PostAsync("/shares/" + id, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Password"] = password,
            ["__RequestVerificationToken"] = ClientBrowser.FormToken(html),
        }), Ct);
    }

    public Task<HttpResponseMessage> DownloadAsync(string id, string? path = null) =>
        Http.GetAsync("/shares/" + id + "/download" + (path == null ? "" : "?path=" + Uri.EscapeDataString(path)), Ct);

    public async Task<HttpResponseMessage> PostChunkAsync(string id, string path, string uploadId, byte[] data, long first, long total, bool overwrite = false)
    {
        var url = "/shares/" + id + "/upload?path=" + Uri.EscapeDataString(path) + "&id=" + uploadId + (overwrite ? "&overwrite=true" : "");
        var content = new ByteArrayContent(data);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        content.Headers.ContentRange = new System.Net.Http.Headers.ContentRangeHeaderValue(first, first + data.Length - 1, total);
        var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        if (Token != null)
            request.Headers.Add("RequestVerificationToken", Token);
        return await Http.SendAsync(request, Ct);
    }

    public async Task<HttpResponseMessage> CheckAsync(string id, string path, long size)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/shares/" + id + "/upload/check")
        {
            Content = JsonContent.Create(new { files = new[] { new { path, size } } }),
        };
        if (Token != null)
            request.Headers.Add("RequestVerificationToken", Token);
        return await Http.SendAsync(request, Ct);
    }

    public void Dispose() => Http.Dispose();

    [GeneratedRegex("data-token=\"([^\"]+)\"")]
    private static partial Regex DataTokenRegex();
}
