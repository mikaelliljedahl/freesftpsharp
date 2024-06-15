using FxSsh.SshServerModule;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces;
using System;

var builder = WebApplication.CreateBuilder(args);
Log.Logger = new LoggerConfiguration()
                      .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                      .MinimumLevel.Override("System", LogEventLevel.Warning)
                      .Enrich.FromLogContext()
                      .WriteTo.File("log.txt", rollingInterval: RollingInterval.Day)
                  //.Enrich.WithExceptionDetails(new DestructuringOptionsBuilder()
                  //.WithDefaultDestructurers()
                  //.WithDestructurers(new[] { new DbUpdateExceptionDestructurer() }))
                  .CreateLogger();
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddHostedService<HostedServer>();

builder.Services.AddSingleton<ISettingsRepository, SettingsRepository>();
builder.Services.AddSingleton<IFileSystemFactory, LocalFileSystemFactory>();
builder.Logging.AddSerilog(Log.Logger);

Log.Information("Starting host service");
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

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseEndpoints(endpoints =>
{
    endpoints.MapBlazorHub();
    endpoints.MapFallbackToPage("/_Host");
});


try
{
    Log.Information("Starting service");
    app.Run();
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

