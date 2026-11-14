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
using SshServerModule.Storage;
using SshServerModule.Events;
using SshServerModule.Connections;

using FxSshSftpServer.Security;

if (AdminPasswordCommand.IsRequested(args))
{
    return AdminPasswordCommand.RunOnConsole();
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
builder.Services.AddAdminDataProtection(builder.Configuration);

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
Log.Debug("AddSshServerStorage...");
builder.Services.AddSshServerStorage();
builder.Services.AddLocalDiskStorage(); // the "local" storage provider

Log.Debug("builder.Build()...");
var app = builder.Build();

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
app.MapRazorPages(); // Login, Logout, Error
app.MapRazorComponents<FxSshSftpServer.Components.App>()
    .AddInteractiveServerRenderMode(); // also maps the Blazor hub (/_blazor); the fallback policy needs a login for it


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
