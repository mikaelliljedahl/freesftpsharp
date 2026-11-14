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
using SshServerModule.Storage;
using SshServerModule.Events;
using SshServerModule.Connections;
using SshServer.Settings.Sql;
using FxSsh.SshServerModule.Cli;
using SshServer.Interfaces.Users;

// "user add|list|remove" manages the users in the settings database and exits. It does not start the server.
if (UserCommand.IsRequested(args))
    return RunUserCommand(args);

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
    services.AddSshServerEvents();
    services.AddSshServerStorage();
    services.AddLocalDiskStorage();
    services.AddHostedService<HostedServer>();
    services.AddSshServerSecurity();
    services.AddSshServerConnections();
    services.AddSshServerListenOptions();
})
.RunConsoleAsync();

return 0;

static int RunUserCommand(string[] args)
{
    // The same configuration as the server start (appsettings.json, environment), so the same settings database is used.
    // The command line is not part of it: "user add ... --root ..." is not configuration.
    var configuration = new ConfigurationBuilder()
        .SetBasePath(AppContext.BaseDirectory)
        .AddJsonFile("appsettings.json", optional: true)
        .AddEnvironmentVariables()
        .Build();

    try
    {
        // With the event bus, so that the audit log has the changes of the command. Disposing the provider delivers them.
        using var provider = new ServiceCollection().AddLogging().AddSshServerSettings(configuration).AddSshServerEvents().BuildServiceProvider();
        return UserCommand.Run(args, provider.GetRequiredService<UserAdministrationService>(),
            Console.In, Console.Out, Console.Error,
            interactive: !Console.IsInputRedirected, promptHidden: ReadHidden);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"The user command failed: {ex.Message}");
        return 1;
    }
}

static string ReadHidden(string prompt)
{
    Console.Error.Write(prompt);
    var builder = new System.Text.StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter)
            break;
        if (key.Key == ConsoleKey.Backspace)
        {
            if (builder.Length > 0)
                builder.Length--;
            continue;
        }
        if (!char.IsControl(key.KeyChar))
            builder.Append(key.KeyChar);
    }
    Console.Error.WriteLine();
    return builder.ToString();
}
