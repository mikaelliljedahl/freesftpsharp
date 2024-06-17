using FxSsh.SshServerModule;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;

namespace SshServer.Settings.LiteDb
{
    public static class Startup
    {
        public static IServiceCollection AddSshServerSettingsLiteDb(this IServiceCollection services)
        {

            services.AddSingleton<ISettingsRepository, SettingsRepository>();
            return services;
        }
    }
}
