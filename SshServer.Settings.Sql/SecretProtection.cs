using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces.Security;

namespace SshServer.Settings.Sql;

/// <summary>
/// The ASP.NET Core data protection of the hosts: it encrypts the secrets of the storage configurations in the settings
/// database (<see cref="DataProtectionSecretProtector"/>, issue #56) and protects the admin login cookie and the
/// antiforgery tokens. The keys are stored in <c>DataProtection:KeysPath</c> (default <c>keys</c> next to the program),
/// so a login and a stored secret survive a restart. Two hosts that share a settings database must share this directory.
/// No key is created before the first secret or login needs one.
/// </summary>
public static class SecretProtection
{
    public const string KeysPathKey = "DataProtection:KeysPath";
    public const string DefaultKeysDirectory = "keys";
    public const string ApplicationName = "FreeSftpSharp.Admin";

    public static IServiceCollection AddSshServerSecretProtection(this IServiceCollection services, IConfiguration configuration)
    {
        var configured = configuration[KeysPathKey];
        var keysPath = Path.GetFullPath(string.IsNullOrWhiteSpace(configured) ? DefaultKeysDirectory : configured,
            AppContext.BaseDirectory);

        var builder = services.AddDataProtection()
            .SetApplicationName(ApplicationName)
            .PersistKeysToFileSystem(new DirectoryInfo(keysPath));

        // On Windows the keys are encrypted with DPAPI. On other platforms they are stored unencrypted, and
        // ASP.NET Core logs a warning about it: protect the directory with file permissions.
        if (OperatingSystem.IsWindows())
            builder.ProtectKeysWithDpapi();

        services.Replace(ServiceDescriptor.Singleton<ISecretProtector, DataProtectionSecretProtector>());
        return services;
    }
}

/// <summary>An <see cref="ISecretProtector"/> on ASP.NET Core data protection, with its own purpose.</summary>
public sealed class DataProtectionSecretProtector : ISecretProtector
{
    private const string Purpose = "FreeSftpSharp.StorageSecrets.v1";

    private readonly IDataProtector _protector;

    public DataProtectionSecretProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector(Purpose);
    }

    public string Protect(string plaintext) => _protector.Protect(plaintext);

    public string Unprotect(string protectedValue) => _protector.Unprotect(protectedValue);
}
