using FxSsh.SshServerModule.Security;
using System;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

using Serilog;

using FxSsh.SshServerModule;

using SshServer.Settings.Sql;
using SshServer.Filesystem.LocalDisk;
using SshServer.Filesystem.AzureBlob;
using SshServer.Filesystem.Gcs;
using SshServer.Filesystem.S3;
using SshServer.Filesystem.Encrypted;
using SshServerModule.Storage;
using SshServerModule.Events;
using SshServerModule.Connections;
using SshServer.Webhooks;
using SshServer.TwoFactor;
using SshServer.EventRules;
using SshServer.Observability;
using FreeSftpSharp.Ftp;
using SshServer.Api;
using FreeSftpSharp.WebDav;

using FxSshSftpServer.Security;
using FxSshSftpServer.WebClient;

if (FxSsh.SshServerModule.Cli.VersionCommand.IsRequested(args))
{
    Console.WriteLine(FxSsh.SshServerModule.Cli.VersionCommand.Describe(typeof(Program).Assembly));
    return 0;
}

if (AdminPasswordCommand.IsRequested(args))
{
    return AdminPasswordCommand.RunOnConsole();
}

if (AdminCreateCommand.IsRequested(args))
{
    return AdminCreateCommand.RunOnConsole(args);
}

// The bootstrap logger reports errors that happen before the real logger is configured from appsettings.json.
Log.Logger = new LoggerConfiguration().WriteTo.Console().CreateBootstrapLogger();

var builder = WebApplication.CreateBuilder(args);
Log.Logger = new LoggerConfiguration()
                      .ReadFrom.Configuration(LogFilePaths.MakeAbsolute(builder.Configuration))
                      .Enrich.FromLogContext()
                      .CreateLogger();

builder.Logging.AddSerilog(Log.Logger);

Log.Information("Starting host service");

Log.Debug("AddRazorPages...");
builder.Services.AddRazorPages();

Log.Debug("AddAdminAuthentication...");
builder.Services.AddAdminAuthentication(builder.Configuration);
builder.Services.AddServerDataProtection(builder.Configuration); // also encrypts the webhook, storage and TOTP secrets
builder.Services.AddWebClient(builder.Configuration); // the web client of the SFTP users (#69) at /client: off unless WebClient:Enabled

Log.Debug("AddRazorComponents...");
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<FxSshSftpServer.Components.Shared.ToastService>();

Log.Debug("AddHostedService<HostedServer>...");
builder.Services.AddHostedService<HostedServer>();
builder.Services.AddSshServerSecurity(); // auto-ban state, IIpBanService for the admin UI
builder.Services.AddSshServerConnections(); // the open connections, shared with the admin UI
builder.Services.AddSshServerListenOptions(); // SshServer:Port / SshServer:BindToAddress override the stored settings

Log.Debug("AddSshServerSettings...");
builder.Services.AddSshServerSettings(builder.Configuration);
Log.Debug("AddSshServerEvents...");
builder.Services.AddSshServerEvents(); // event bus; the audit log comes with AddSshServerSettings
builder.Services.AddWebhooks(builder.Configuration); // webhooks (#66): nothing is sent until an admin adds one
builder.Services.AddTwoFactor(builder.Configuration); // TOTP second factor (#63): off until a user or administrator sets up an app
builder.Services.AddEventRules(builder.Configuration); // event rules (#68): nothing runs until an admin adds a rule; commands are off
builder.Services.AddSshServerObservability(builder.Configuration); // metrics; /metrics, /healthz, /readyz and OTLP only when configured
builder.Services.AddRestApi(builder.Configuration); // the REST API under /api/v1 (#67), only with Api:Enabled
Log.Debug("AddSshServerStorage...");
builder.Services.AddSshServerStorage();
builder.Services.AddLocalDiskStorage(); // the "local" storage provider
builder.Services.AddS3Storage(); // the "s3" storage provider (used only when a user or virtual folder selects it)
builder.Services.AddAzureBlobStorage(); // the "azure-blob" storage provider (used only when a user or virtual folder selects it)
builder.Services.AddGcsStorage(); // the "gcs" storage provider (used only when a user or virtual folder selects it)
builder.Services.AddEncryptedLocalStorage(); // "local-encrypted"; the default of users without a storage configuration only with Storage:Encryption:Enabled
builder.Services.AddWebDav(builder.Configuration); // WebDAV (#71): off until WebDav:Enabled is true
builder.Services.AddFtp(builder.Configuration); // FTP and FTPS (#72): off until Ftp:Enabled is true

Log.Debug("builder.Build()...");
var app = builder.Build();

app.UseSshServerObservability(); // before the login: probes and scrapers have no cookie
app.MapWebDav(); // WebDAV has its own Basic login; nothing is mapped while it is off

// The web client: 404 when it is off, its security headers when it is on. Before the admin gate: it needs no administrator.
app.UseWebClient();

// Without an admin credential the whole UI answers 503 (the SSH server still runs).
app.UseAdminUiRequiresCredential();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

Log.Debug("UseHttpsRedirection()...");
app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

// The CSS, fonts and scripts (wwwroot and _framework/blazor.web.js) are local files; the login page needs them before a login.
app.MapStaticAssets().AllowAnonymous();
app.MapRazorPages(); // Login, Logout, Error, and the pages of the web client (Pages/Client)
app.MapWebClient(); // the endpoints of the web client (/client/api)
app.MapRazorComponents<FxSshSftpServer.Components.App>()
    .AddInteractiveServerRenderMode(); // also maps the Blazor hub (/_blazor); the fallback policy needs a login for it
app.MapRestApi(); // bearer token or API key, never the login cookie


try
{
    Log.Information("Starting service...");
    app.Run();
    Log.Information("Service has finished.");
    return 0;
}
catch (Exception ex)
{
    Log.Fatal(ex, "Service terminated unexpectedly");
    return 1;
}
finally
{
    Log.CloseAndFlush();
}


/// <summary>Visible to the tests (WebApplicationFactory&lt;Program&gt;).</summary>
public partial class Program { }
