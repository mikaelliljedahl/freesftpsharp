using System;
using System.Threading.Tasks;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

using Serilog;
using Serilog.Events;
using Serilog.Sinks.File;
using Serilog.Sinks.HtmlFile;

using FxSsh.SshServerModule;

using SshServer.Interfaces;
using SshServer.Filesystem.LocalDisk;

Log.Logger = new LoggerConfiguration()
                      .WriteTo.Console(theme: Serilog.Sinks.SystemConsole.Themes.AnsiConsoleTheme.Code)
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


await new HostBuilder()
.ConfigureServices((hostContext, services) =>
{
    services.AddLogging();
    Log.Information("Starting host service");
    services.AddLogging(configure =>
    {
        configure.AddSerilog(Log.Logger);
    });
    services.AddSingleton<ISettingsRepository, SettingsRepository>();
    services.AddSingleton<IFileSystemFactory, LocalFileSystemFactory>();
    services.AddHostedService<HostedServer>();


})
.RunConsoleAsync();
