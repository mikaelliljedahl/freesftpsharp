#nullable enable
using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Authentication;

namespace SshServerModule.Authentication;

public static class AuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// The credential check of the protocols (issue #64): <see cref="IUserAuthenticator"/> with the
    /// <see cref="DatabaseAuthenticationProvider"/>, and the providers of the plug-ins (AddHttpAuthHook,
    /// AddLdapAuthentication) in the order of <c>Auth:Providers</c>. Without a plug-in only the database checks the
    /// logins, as before. Needs the <c>ISettingsRepository</c> (AddSshServerSettings).
    /// </summary>
    public static IServiceCollection AddSshServerAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        services.TryAddSingleton(TimeProvider.System);
        services.AddOptions<AuthenticationOptions>().Configure(o => AuthenticationOptions.Bind(o, configuration)).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<AuthenticationOptions>, AuthenticationOptionsValidator>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthenticationProvider, DatabaseAuthenticationProvider>());
        services.TryAddSingleton<IUserAuthenticator, UserAuthenticator>();
        return services;
    }
}
