using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Authentication;

namespace SshServer.Authentication.Ldap;

public static class LdapAuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// The LDAP / Active Directory provider (issue #64) as the <see cref="IAuthenticationProvider"/> "ldap". Nothing is
    /// registered while <c>Auth:Ldap:Server</c> is empty. The host also calls AddSshServerAuthentication, which puts the
    /// provider in the order of <c>Auth:Providers</c>.
    /// </summary>
    public static IServiceCollection AddLdapAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        var options = new LdapAuthenticationOptions();
        LdapAuthenticationOptions.Bind(options, configuration);
        if (!options.Enabled)
            return services;

        services.AddOptions<LdapAuthenticationOptions>().Configure(o => LdapAuthenticationOptions.Bind(o, configuration)).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<LdapAuthenticationOptions>, LdapAuthenticationOptionsValidator>());
        services.TryAddSingleton<ILdapConnector, ProtocolsLdapConnector>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthenticationProvider, LdapAuthenticationProvider>());
        return services;
    }
}
