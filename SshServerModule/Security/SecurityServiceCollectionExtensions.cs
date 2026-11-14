using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces;
using System;

namespace FxSsh.SshServerModule.Security
{
    public static class SecurityServiceCollectionExtensions
    {
        /// <summary>
        /// Registers the auto-ban state (<see cref="LoginBanTracker"/>) as a singleton, also as
        /// <see cref="IIpBanService"/> for the admin UI, and the <see cref="PasswordLoginService"/> of the protocols that are
        /// not SSH. Call it together with AddHostedService&lt;HostedServer&gt;.
        /// </summary>
        public static IServiceCollection AddSshServerSecurity(this IServiceCollection services)
        {
            services.TryAddSingleton(TimeProvider.System);
            services.TryAddSingleton(sp => new LoginBanTracker(sp.GetRequiredService<TimeProvider>()));
            services.TryAddSingleton<IIpBanService>(sp => sp.GetRequiredService<LoginBanTracker>());
            services.TryAddSingleton<PasswordLoginService>(); // the password login of WebDAV and FTP
            return services;
        }
    }
}
