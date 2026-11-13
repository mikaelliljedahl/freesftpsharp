using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;

namespace SshServer.Filesystem.LocalDisk
{
    public static class Startup
    {
        public static IServiceCollection AddLocalFileSystemHosting(this IServiceCollection services)
        {
            services.AddSingleton<IFileSystemFactory, LocalFileSystemFactory>();
            return services;
        }
    }
}
