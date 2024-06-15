using Microsoft.Extensions.DependencyInjection;

namespace SshServer.Settings.LiteDb
{
    public static class Startup
    {
        public static IServiceCollection AddSshServerSettingsLiteDb(this IServiceCollection services)
        {

            return services;
        }
    }
}
