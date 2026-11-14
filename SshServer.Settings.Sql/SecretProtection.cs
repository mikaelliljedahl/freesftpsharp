using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces.Security;

namespace SshServer.Settings.Sql;

/// <summary>
/// The encryption of the secrets of the storage configurations in the settings database (issue #56), with the ASP.NET
/// Core data protection of the host (<c>AddServerDataProtection</c>: the keys in <c>DataProtection:KeysPath</c>, the
/// same key ring as the login cookie and the webhook secrets). Two hosts that share a settings database must share
/// that directory. A host without data protection keeps the <c>UnavailableSecretProtector</c>: a storage
/// configuration without secrets still works.
/// </summary>
public static class SecretProtection
{
    public static IServiceCollection AddSshServerSecretProtection(this IServiceCollection services)
    {
        services.Replace(ServiceDescriptor.Singleton<ISecretProtector>(sp =>
            sp.GetService<IDataProtectionProvider>() is { } provider
                ? new DataProtectionSecretProtector(provider)
                : new NoDataProtection()));
        return services;
    }

    /// <summary>The same behaviour as <c>UnavailableSecretProtector</c> of the storage core, which this project does not reference.</summary>
    private sealed class NoDataProtection : ISecretProtector
    {
        public string Protect(string plaintext)
            => throw new InvalidOperationException("No data protection is registered (AddServerDataProtection), so a secret cannot be stored.");

        public string Unprotect(string protectedValue)
            => throw new System.Security.Cryptography.CryptographicException("No data protection is registered (AddServerDataProtection), so a stored secret cannot be read.");
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
