using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Authentication;

namespace SshServer.Authentication.Http;

public static class HttpAuthHookServiceCollectionExtensions
{
    /// <summary>
    /// The external HTTP authentication hook (issue #64) as the <see cref="IAuthenticationProvider"/> "http". Nothing is
    /// registered while <c>Auth:HttpHook:Url</c> is empty. The host also calls AddSshServerAuthentication, which puts
    /// the provider in the order of <c>Auth:Providers</c>.
    /// </summary>
    public static IServiceCollection AddHttpAuthHook(this IServiceCollection services, IConfiguration configuration)
    {
        var options = new HttpAuthHookOptions();
        HttpAuthHookOptions.Bind(options, configuration);
        if (!options.Enabled)
            return services;

        services.TryAddSingleton(TimeProvider.System);
        services.AddOptions<HttpAuthHookOptions>().Configure(o => HttpAuthHookOptions.Bind(o, configuration)).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<HttpAuthHookOptions>, HttpAuthHookOptionsValidator>());
        services.AddHttpClient(HttpAuthHookProvider.HttpClientName)
            .ConfigureHttpClient(client => client.Timeout = Timeout.InfiniteTimeSpan) // the provider has its own timeout
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                AllowAutoRedirect = false, // a redirect is a refusal; the password never goes to another URL
                UseCookies = false,
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            })
            .RemoveAllLoggers(); // the default request logs would show the URL
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthenticationProvider, HttpAuthHookProvider>());
        return services;
    }
}
