using System;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

using Serilog;
using Serilog.Events;
using Serilog.Sinks.File;
using Serilog.Sinks.HtmlFile;

using FxSsh.SshServerModule;

using SshServer.Settings.Sql;
using SshServer.Filesystem.LocalDisk;

var builder = WebApplication.CreateBuilder(args);
Log.Logger = new LoggerConfiguration()
                      //.MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                      //.MinimumLevel.Override("System", LogEventLevel.Warning)
                      .Enrich.FromLogContext()
                      //.WriteTo.File("FxSshServer.txt", rollingInterval: RollingInterval.Day)
                      .WriteTo.File("FxSshServer.txt", rollOnFileSizeLimit: true, fileSizeLimitBytes: 10_000_000)
                      .WriteTo.HtmlFile(path: "logsHtml/FxSshServer.html", fileSizeLimitBytes: 10_000_000)
                  //.Enrich.WithExceptionDetails(new DestructuringOptionsBuilder()
                  //.WithDefaultDestructurers()
                  //.WithDestructurers(new[] { new DbUpdateExceptionDestructurer() }))
                  .CreateLogger();

builder.Logging.AddSerilog(Log.Logger);

Log.Information("Starting host service");

Log.Information("AddRazorPages...");
builder.Services.AddRazorPages();

Log.Information("AddServerSideBlazor...");
builder.Services.AddServerSideBlazor();

Log.Information("AddHostedService<HostedServer>...");
builder.Services.AddHostedService<HostedServer>();

Log.Warning("AddSshServerSettings...");
builder.Services.AddSshServerSettings(builder.Configuration);
Log.Warning("AddLocalFileSystemHosting...");
builder.Services.AddLocalFileSystemHosting();

Log.Warning("builder.Build()...");
var app = builder.Build();


if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

Log.Warning("UseHttpsRedirection()...");
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

Log.Warning("UseEndpoints(...)...");
app.UseEndpoints(endpoints =>
{
    endpoints.MapBlazorHub();
    endpoints.MapFallbackToPage("/_Host");
});


try
{
    Log.Warning("Starting service...");
    app.Run();
    Log.Warning("Service has finished.");
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

