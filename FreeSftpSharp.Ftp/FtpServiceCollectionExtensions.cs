using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.Users;
using SshServerModule.Connections;
using SshServerModule.Proxy;

namespace FreeSftpSharp.Ftp;

public static class FtpServiceCollectionExtensions
{
    /// <summary>
    /// The FTP and FTPS server (issue #72), from the <c>Ftp</c> section (<see cref="FtpOptions"/>). Off by default: then the
    /// hosted service opens no port. Without <c>Ftp:Tls:CertificatePath</c> it takes the Kestrel certificate
    /// (<c>Kestrel:Certificates:Default</c>). It needs the shared services of the host: the settings (users), the storage
    /// factory, the connections, the security services and, for the events, the event bus.
    /// </summary>
    public static IServiceCollection AddFtp(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<FtpOptions>()
            .Bind(configuration.GetSection(FtpOptions.SectionName))
            .PostConfigure(options => UseKestrelCertificate(options.Tls, configuration))
            .ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<FtpOptions>, FtpOptionsValidator>());
        services.AddSshServerSecurity();
        services.AddSshServerConnections();
        services.TryAddSingleton<IEffectiveUserSettingsService>(sp => new EffectiveUserSettingsService(sp.GetRequiredService<ISettingsRepository>()));
        // The PROXY protocol of a load balancer (#75), the same Proxy section as the SSH listener: off until Proxy:AllowedSources is set.
        services.TryAddSingleton(_ => ProxyProtocolOptions.FromConfiguration(configuration));
        services.TryAddSingleton<FtpPassivePorts>();
        services.TryAddSingleton<FtpCertificate>();
        services.TryAddSingleton<FtpServices>();
        services.TryAddSingleton(sp => new FtpServer(sp.GetRequiredService<FtpServices>(), sp.GetRequiredService<ILogger<FtpServer>>()));
        services.AddHostedService(sp => sp.GetRequiredService<FtpServer>());
        return services;
    }

    private static void UseKestrelCertificate(FtpTlsOptions tls, IConfiguration configuration)
    {
        if (!string.IsNullOrWhiteSpace(tls.CertificatePath))
            return;
        var kestrel = configuration.GetSection("Kestrel:Certificates:Default");
        if (string.IsNullOrWhiteSpace(kestrel["Path"]))
            return;
        tls.CertificatePath = kestrel["Path"];
        tls.CertificateKeyPath = kestrel["KeyPath"];
        tls.CertificatePassword = kestrel["Password"];
    }
}
