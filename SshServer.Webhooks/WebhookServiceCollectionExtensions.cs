using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Events;

namespace SshServer.Webhooks;

public static class WebhookServiceCollectionExtensions
{
    /// <summary>
    /// The webhooks plug-in (#66): the event sink of the asynchronous webhooks (<see cref="WebhookSink"/>, an outbox in the
    /// settings database), the hook of the synchronous <c>Pre*</c> webhooks (<see cref="WebhookEventHook"/>), the
    /// background sender (<see cref="WebhookDispatcher"/>) and the application service of the admin UI. Nothing is sent
    /// until an admin adds a webhook; with no webhook an event costs no database read and no request. Needs an
    /// <c>IWebhookStore</c> (AddSshServerSettings) and the event bus (AddSshServerEvents). The host configures where the
    /// data protection keys are (they encrypt the secrets); options in the section <c>Webhooks</c>.
    /// </summary>
    public static IServiceCollection AddWebhooks(this IServiceCollection services, IConfiguration configuration)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddOptions<WebhookOptions>().Configure(o => WebhookOptions.Bind(o, configuration)).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<WebhookOptions>, WebhookOptionsValidator>());
        services.AddDataProtection();

        services.AddHttpClient(WebhookSender.HttpClientName)
            .ConfigureHttpClient(client => client.Timeout = Timeout.InfiniteTimeSpan) // each request has the timeout of its webhook
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                AllowAutoRedirect = false, // never follow a redirect
                UseCookies = false,
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            })
            .RemoveAllLoggers(); // the default request logs would show the URLs

        services.TryAddSingleton<WebhookSecretProtector>();
        services.TryAddSingleton<WebhookCatalog>();
        services.TryAddSingleton<WebhookSender>();
        services.TryAddSingleton<WebhookDispatchSignal>();
        services.TryAddSingleton(_ => new WebhookRetrySchedule());
        services.TryAddSingleton<WebhookAdministrationService>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventSink, WebhookSink>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventHook, WebhookEventHook>());
        services.AddHostedService<WebhookDispatcher>();
        return services;
    }
}
