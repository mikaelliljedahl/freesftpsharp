using Microsoft.AspNetCore.DataProtection;
using System;
using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace FxSshSftpServer.Security;

/// <summary>
/// Stores the ASP.NET Core data protection keys (they protect the admin login cookie and the antiforgery tokens)
/// in a known directory, so that a login survives a restart of the app.
/// </summary>
public static class DataProtectionSetup
{
    public const string KeysPathKey = "DataProtection:KeysPath";
    public const string DefaultKeysDirectory = "keys";
    /// <summary>Keeps the keys in memory only. For tests: a login does not survive a restart.</summary>
    public const string EphemeralKey = "DataProtection:Ephemeral";

    public static IServiceCollection AddAdminDataProtection(this IServiceCollection services, IConfiguration configuration)
    {
        if (configuration.GetValue<bool>(EphemeralKey))
        {
            services.AddDataProtection().UseEphemeralDataProtectionProvider();
            return services;
        }

        var configured = configuration[KeysPathKey];
        var keysPath = Path.GetFullPath(string.IsNullOrWhiteSpace(configured) ? DefaultKeysDirectory : configured,
            AppContext.BaseDirectory);

        var builder = services.AddDataProtection()
            .SetApplicationName("FreeSftpSharp.Admin")
            .PersistKeysToFileSystem(new DirectoryInfo(keysPath));

        // On Windows the keys are encrypted with DPAPI. On other platforms they are stored unencrypted, and
        // ASP.NET Core logs a warning about it: protect the directory with file permissions.
        if (OperatingSystem.IsWindows())
            builder.ProtectKeysWithDpapi();

        return services;
    }
}
