using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.DataProtection;
using SshServer.Settings.Sql;

namespace FxSshSftpServer.Security;

/// <summary>
/// Stores the ASP.NET Core data protection keys (they protect the admin login cookie and the antiforgery tokens)
/// in a known directory, so that a login survives a restart of the app. It is the directory and the application name
/// of the stored storage secrets too (<see cref="SecretProtection"/>).
/// </summary>
public static class DataProtectionSetup
{
    public static IServiceCollection AddAdminDataProtection(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDataProtection().UseSshServerKeys(SecretProtection.KeysPath(configuration));
        return services;
    }
}
