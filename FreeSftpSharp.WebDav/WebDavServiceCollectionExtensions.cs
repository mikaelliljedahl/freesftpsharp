using FxSsh.SshServerModule.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Users;
using SshServerModule.Connections;

namespace FreeSftpSharp.WebDav;

public static class WebDavServiceCollectionExtensions
{
    /// <summary>
    /// The WebDAV server (issue #71), from the <c>WebDav</c> section (<see cref="WebDavOptions"/>). Off by default: then it
    /// registers only the options, and <see cref="MapWebDav"/> adds nothing. It needs the shared services of the host:
    /// the settings (users), the storage factory, the connections, the security services and, for the events, the event bus.
    /// </summary>
    public static IServiceCollection AddWebDav(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<WebDavOptions>().Bind(configuration.GetSection(WebDavOptions.SectionName)).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<WebDavOptions>, WebDavOptionsValidator>());
        services.TryAddSingleton(TimeProvider.System);
        services.AddSshServerSecurity();
        services.AddSshServerConnections();
        services.TryAddSingleton<IEffectiveUserSettingsService>(sp => new EffectiveUserSettingsService(sp.GetRequiredService<ISettingsRepository>()));
        services.TryAddSingleton(sp => new WebDavLockManager(sp.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton<WebDavSessionStore>();
        services.TryAddSingleton<WebDavAuthenticator>();
        services.TryAddSingleton<WebDavHandler>();
        services.AddHostedService<WebDavSessionSweeper>();
        return services;
    }

    /// <summary>
    /// Adds the WebDAV branch to the pipeline when <see cref="WebDavOptions.Enabled"/> is set. It is terminal middleware:
    /// call it before the admin UI (its login cookie, HTTPS redirection, antiforgery and routing), because WebDAV has its
    /// own Basic login. With <see cref="WebDavOptions.Port"/>, every request to that port goes to WebDAV.
    /// </summary>
    public static IApplicationBuilder MapWebDav(this IApplicationBuilder app)
    {
        var options = app.ApplicationServices.GetRequiredService<IOptions<WebDavOptions>>().Value;
        var logger = app.ApplicationServices.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(WebDavServiceCollectionExtensions));
        if (!options.Enabled)
        {
            logger.LogInformation("WebDAV is off. Set WebDav:Enabled to true to turn it on.");
            return app;
        }

        var handler = app.ApplicationServices.GetRequiredService<WebDavHandler>();
        app.MapWhen(context => IsWebDavRequest(context, options, handler.Paths), branch => branch.Run(handler.HandleAsync));
        logger.LogInformation("WebDAV is on at {Path}{Port}.", options.NormalizedPath,
            options.Port == 0 ? " on every endpoint of the web host" : $" on port {options.Port}");
        return app;
    }

    private static bool IsWebDavRequest(HttpContext context, WebDavOptions options, WebDavPaths paths) =>
        options.Port != 0 ? context.Connection.LocalPort == options.Port : paths.IsUnderPrefix(context.Request.Path);
}

/// <summary>Ends the idle WebDAV sessions every 30 seconds, and every session at the stop.</summary>
internal sealed class WebDavSessionSweeper : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

    private readonly WebDavSessionStore _sessions;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    public WebDavSessionSweeper(WebDavSessionStore sessions, TimeProvider time, ILogger<WebDavSessionSweeper> logger)
    {
        _sessions = sessions;
        _time = time;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval, _time);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                try
                {
                    await _sessions.RemoveIdleAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Could not end the idle WebDAV sessions.");
                }
            }
        }
        catch (OperationCanceledException)
        {
            // stopping
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);
        await _sessions.EndAllAsync();
    }
}
