using FxSsh.SshServerModule;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces;
using System.Threading.Tasks;

Log.Logger = new LoggerConfiguration()
                      .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                      .MinimumLevel.Override("System", LogEventLevel.Warning)
                      .Enrich.FromLogContext()
                      .WriteTo.File("log.txt", rollingInterval: RollingInterval.Day)
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
