using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.TwoFactor;

namespace SshServer.TwoFactor;

public static class TwoFactorServiceCollectionExtensions
{
    /// <summary>
    /// Registers the TOTP second factor (issue #63): <see cref="TwoFactorService"/>, also as the
    /// <see cref="ITwoFactorVerifier"/> of the SSH server and the admin login, with the settings of <c>Auth:Totp</c>.
    /// Needs the data protection of the host (AddServerDataProtection) and the <see cref="ITwoFactorStore"/> of the
    /// settings (AddSshServerSettings). Nothing changes until a user or administrator sets up an app.
    /// </summary>
    public static IServiceCollection AddTwoFactor(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<TwoFactorOptions>().Configure(o => TwoFactorOptions.Bind(o, configuration)).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<TwoFactorOptions>, TwoFactorOptionsValidator>());
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<TotpSecretProtector>();
        services.TryAddSingleton(sp => new TwoFactorService(
            sp.GetRequiredService<ITwoFactorStore>(),
            sp.GetRequiredService<TotpSecretProtector>(),
            sp.GetRequiredService<IOptions<TwoFactorOptions>>(),
            sp.GetService<TimeProvider>(),
            sp.GetService<Microsoft.Extensions.Logging.ILogger<TwoFactorService>>()));
        services.TryAddSingleton<ITwoFactorVerifier>(sp => sp.GetRequiredService<TwoFactorService>());
        return services;
    }
}
