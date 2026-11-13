using FxSsh.SshServerModule.Security;
using System;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

using Serilog;
using Serilog.Events;
using Serilog.Sinks.File;
using Serilog.Sinks.HtmlFile;

using FxSsh.SshServerModule;

using SshServer.Interfaces;
using SshServer.Filesystem.LocalDisk;
using SshServer.Settings.Sql;

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
.ConfigureAppConfiguration((hostContext, config) =>
{
    config.SetBasePath(AppContext.BaseDirectory)
        .AddJsonFile("appsettings.json", optional: true)
        .AddEnvironmentVariables()
        .AddCommandLine(args, SshServerOptions.SwitchMappings);
})
.ConfigureServices((hostContext, services) =>
{
    services.AddLogging();
    Log.Information("Starting host service");
    services.AddLogging(configure =>
    {
        configure.AddSerilog(Log.Logger);
    });
    services.AddSshServerSettings(hostContext.Configuration);
    services.AddSingleton<IFileSystemFactory, LocalFileSystemFactory>();
    services.AddHostedService<HostedServer>();
    services.AddSshServerSecurity();
    services.AddSshServerListenOptions();


})
.RunConsoleAsync();
