using FxSsh.SshServerModule.Security;
using System;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

using Serilog;

using FxSsh.SshServerModule;

using SshServer.Interfaces;
using SshServer.Filesystem.LocalDisk;
using SshServer.Settings.Sql;

// The bootstrap logger reports errors that happen before the real logger is configured from appsettings.json.
Log.Logger = new LoggerConfiguration().WriteTo.Console().CreateBootstrapLogger();

var configuration = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: true)
    .AddEnvironmentVariables()
    .AddCommandLine(args, SshServerOptions.SwitchMappings)
    .Build();

Log.Logger = new LoggerConfiguration()
                      .ReadFrom.Configuration(LogFilePaths.MakeAbsolute(configuration))
                      .Enrich.FromLogContext()
                      .CreateLogger();

await new HostBuilder()
.ConfigureAppConfiguration((hostContext, config) =>
{
    config.AddConfiguration(configuration);
})
.ConfigureServices((hostContext, services) =>
{
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
