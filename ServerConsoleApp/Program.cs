using FxSsh.SshServerModule;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;
using System;
using System.Threading.Tasks;

namespace ServerConsoleApp
{
    class Program
    {
        static async Task Main(string[] args)
        {
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
                services.AddHostedService<HostedServer>();
            })
            .RunConsoleAsync();
        }
    }
}
