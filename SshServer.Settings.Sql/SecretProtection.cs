using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces.Security;

namespace SshServer.Settings.Sql;

/// <summary>
/// The encryption of the secrets of the storage configurations in the settings database (issue #56), with ASP.NET Core
/// data protection keys in <c>DataProtection:KeysPath</c> (default <c>keys</c> next to the program). The admin UI keeps
/// its login cookie keys in the same directory with the same application name, so one key ring serves both. Two hosts
/// that share a settings database must share this directory.
/// <para>
/// Nothing is created at start: the key ring is opened at the first secret, so a server without secrets (the
/// zero-configuration start) writes no key file.
/// </para>
/// </summary>
public static class SecretProtection
{
    public const string KeysPathKey = "DataProtection:KeysPath";
    public const string DefaultKeysDirectory = "keys";
    public const string ApplicationName = "FreeSftpSharp.Admin";

    /// <summary>The full path of the data protection keys directory.</summary>
    public static string KeysPath(IConfiguration configuration)
    {
        var configured = configuration[KeysPathKey];
        return Path.GetFullPath(string.IsNullOrWhiteSpace(configured) ? DefaultKeysDirectory : configured, AppContext.BaseDirectory);
    }

    /// <summary>
    /// Configures a data protection builder for the keys directory: the application name and, on Windows, DPAPI. On
    /// other platforms the keys are stored unencrypted (ASP.NET Core logs a warning): protect the directory with file
    /// permissions.
    /// </summary>
    public static IDataProtectionBuilder UseSshServerKeys(this IDataProtectionBuilder builder, string keysPath)
    {
        builder.SetApplicationName(ApplicationName).PersistKeysToFileSystem(new DirectoryInfo(keysPath));
        if (OperatingSystem.IsWindows())
            builder.ProtectKeysWithDpapi();
        return builder;
    }

    /// <summary>Registers <see cref="ISecretProtector"/> on the data protection keys of <see cref="KeysPath"/>.</summary>
    public static IServiceCollection AddSshServerSecretProtection(this IServiceCollection services, IConfiguration configuration)
    {
        var keysPath = KeysPath(configuration);
        services.Replace(ServiceDescriptor.Singleton<ISecretProtector>(_ => new DataProtectionSecretProtector(
            () => DataProtectionProvider.Create(new DirectoryInfo(keysPath), builder => builder.UseSshServerKeys(keysPath)))));
        return services;
    }
}

/// <summary>An <see cref="ISecretProtector"/> on ASP.NET Core data protection, with its own purpose.</summary>
public sealed class DataProtectionSecretProtector : ISecretProtector
{
    private const string Purpose = "FreeSftpSharp.StorageSecrets.v1";

    private readonly Lazy<IDataProtector> _protector;

    /// <param name="provider">Creates the data protection provider at the first secret.</param>
    public DataProtectionSecretProtector(Func<IDataProtectionProvider> provider)
    {
        _protector = new Lazy<IDataProtector>(() => provider().CreateProtector(Purpose));
    }

    public DataProtectionSecretProtector(IDataProtectionProvider provider)
        : this(() => provider)
    {
    }

    public string Protect(string plaintext) => _protector.Value.Protect(plaintext);

    public string Unprotect(string protectedValue) => _protector.Value.Unprotect(protectedValue);
}
