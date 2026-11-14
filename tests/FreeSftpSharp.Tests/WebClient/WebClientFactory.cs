using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using FreeSftpSharp.Tests.Events;
using FreeSftpSharp.Tests.WebUi;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.WebClient;

/// <summary>
/// The admin host with the web client on (<c>WebClient:Enabled</c>), in memory like <see cref="AdminUiFactory"/>. The users
/// have the default storage (the local disk) in a temporary directory; every event is recorded in <see cref="Events"/>.
/// </summary>
public sealed partial class WebClientFactory : AdminUiFactory
{
    public const string UserPassword = "User-Password-42";

    private static readonly string UserPasswordHash = PasswordHasher.Hash(UserPassword, PasswordHasher.MinimumIterations);

    public string RootDirectory { get; } = Path.Combine(Path.GetTempPath(), "fss-webclient-" + Guid.NewGuid().ToString("N"));

    public RecordingEventSink Events { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("WebClient:Enabled", "true");
        builder.UseSetting("WebClient:MaxFailedLogins", "1000");
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<IEventSink>(Events);
            // The quota counters in memory: the SQL store would use the default database next to the app.
            services.RemoveAll<IQuotaUsageStore>();
            services.AddSingleton<IQuotaUsageStore>(new SshServerModule.Quotas.InMemoryQuotaUsageStore());
        });
    }

    public ISettingsRepository Repository => Services.GetRequiredService<ISettingsRepository>();

    /// <summary>Adds a user with <see cref="UserPassword"/> and its own directory; returns the directory.</summary>
    public string AddUser(string name, Dictionary<string, FilePermissions>? permissions = null, DiskQuota? quota = null, Action<User>? change = null)
    {
        var root = Path.Combine(RootDirectory, name);
        Directory.CreateDirectory(root);
        var user = new User
        {
            Username = name,
            UserRootDirectory = root,
            HashedPassword = UserPasswordHash,
            Permissions = permissions,
            DiskQuota = quota,
        };
        change?.Invoke(user);
        Assert.True(Repository.AddUser(user));
        return root;
    }

    /// <summary>A browser that is logged in to the web client as <paramref name="name"/>.</summary>
    public async Task<ClientBrowser> LogInAsync(string name, string password = UserPassword)
    {
        var browser = new ClientBrowser(CreateBrowser());
        var response = await browser.LogInAsync(name, password);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return browser;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try
        {
            Directory.Delete(RootDirectory, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}

/// <summary>An HTTP client with cookies and the antiforgery token of the file browser.</summary>
public sealed partial class ClientBrowser : IDisposable
{
    public ClientBrowser(HttpClient http)
    {
        Http = http;
    }

    public HttpClient Http { get; }

    /// <summary>The token of the last file browser page (<see cref="OpenFilesAsync"/>).</summary>
    public string? Token { get; private set; }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public async Task<HttpResponseMessage> LogInAsync(string name, string password)
    {
        var page = await Http.GetAsync("/client/login", Ct);
        var token = FormToken(await page.Content.ReadAsStringAsync(Ct));
        return await Http.PostAsync("/client/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["UserName"] = name,
            ["Password"] = password,
            ["__RequestVerificationToken"] = token,
        }), Ct);
    }

    /// <summary>Opens the file browser page of a directory (and keeps its antiforgery token).</summary>
    public async Task<(HttpStatusCode Status, string Html)> OpenFilesAsync(string path = "/")
    {
        var response = await Http.GetAsync("/client?path=" + Uri.EscapeDataString(path), Ct);
        var html = await response.Content.ReadAsStringAsync(Ct);
        var match = DataTokenRegex().Match(html);
        if (match.Success)
            Token = WebUtility.HtmlDecode(match.Groups[1].Value);
        return (response.StatusCode, html);
    }

    public async Task<string> RequireTokenAsync()
    {
        if (Token == null)
            await OpenFilesAsync();
        return Token ?? throw new InvalidOperationException("The file browser has no token.");
    }

    public async Task<HttpResponseMessage> PostJsonAsync(string url, object body)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = JsonContent.Create(body) };
        request.Headers.Add("RequestVerificationToken", await RequireTokenAsync());
        return await Http.SendAsync(request, Ct);
    }

    public async Task<HttpResponseMessage> PostChunkAsync(string path, string id, byte[] data, long first, long total, bool overwrite = false)
    {
        var url = "/client/api/upload?path=" + Uri.EscapeDataString(path) + "&id=" + id + (overwrite ? "&overwrite=true" : "");
        var content = new ByteArrayContent(data);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        content.Headers.ContentRange = total == 0
            ? new System.Net.Http.Headers.ContentRangeHeaderValue(0) { }
            : new System.Net.Http.Headers.ContentRangeHeaderValue(first, first + data.Length - 1, total);
        var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        request.Headers.Add("RequestVerificationToken", await RequireTokenAsync());
        return await Http.SendAsync(request, Ct);
    }

    /// <summary>Uploads a file in chunks of <paramref name="chunkSize"/> bytes; asserts that every chunk is accepted.</summary>
    public async Task UploadAsync(string path, byte[] data, int chunkSize = 1024 * 1024)
    {
        var id = Guid.NewGuid().ToString("N");
        for (var first = 0; first < data.Length; first += chunkSize)
        {
            var chunk = data.AsSpan(first, Math.Min(chunkSize, data.Length - first)).ToArray();
            var response = await PostChunkAsync(path, id, chunk, first, data.Length);
            Assert.True(response.IsSuccessStatusCode, $"chunk at {first}: {response.StatusCode} {await response.Content.ReadAsStringAsync(Ct)}");
        }
    }

    public static string FormToken(string html) =>
        WebUtility.HtmlDecode(FormTokenRegex().Match(html).Groups[1].Value);

    public void Dispose() => Http.Dispose();

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex FormTokenRegex();

    [GeneratedRegex("data-token=\"([^\"]+)\"")]
    private static partial Regex DataTokenRegex();
}
