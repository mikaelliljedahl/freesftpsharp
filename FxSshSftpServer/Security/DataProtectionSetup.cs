using Microsoft.AspNetCore.DataProtection;
using System;
using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Settings.Sql.Cluster;

namespace FxSshSftpServer.Security;

/// <summary>
/// Stores the ASP.NET Core data protection keys (they protect the admin login cookie, the antiforgery tokens, and the
/// webhook secrets and storage secrets (#56) in the settings database) in a known directory, so that a login survives a restart of the app and
/// a stored webhook secret stays readable. Both hosts (admin UI and console) use this, with the same application name,
/// so they read the same secrets when they share the directory.
/// <para>
/// With <c>DataProtection:Store</c> = <c>Database</c> (issue #75) the keys are in the settings database instead
/// (a SQL provider), so several nodes on one database share them without a shared directory. They are stored as
/// ASP.NET Core writes them (not encrypted outside Windows DPAPI, which one machine only could read): protect the
/// database. The default is <c>FileSystem</c>.
/// </para>
/// </summary>
public static class DataProtectionSetup
{
    public const string KeysPathKey = "DataProtection:KeysPath";
    public const string DefaultKeysDirectory = "keys";
    public const string StoreKey = "DataProtection:Store";

    public static IServiceCollection AddServerDataProtection(this IServiceCollection services, IConfiguration configuration)
    {
        var store = configuration[StoreKey]?.Trim();
        var builder = services.AddDataProtection().SetApplicationName("FreeSftpSharp.Admin");
        if (string.Equals(store, "Database", StringComparison.OrdinalIgnoreCase))
        {
            builder.PersistKeysToSettingsDatabase();
            return services;
        }
        if (!string.IsNullOrEmpty(store) && !string.Equals(store, "FileSystem", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Unknown {StoreKey} '{store}'. Supported values: FileSystem, Database.");

        var configured = configuration[KeysPathKey];
        var keysPath = Path.GetFullPath(string.IsNullOrWhiteSpace(configured) ? DefaultKeysDirectory : configured,
            AppContext.BaseDirectory);
        builder.PersistKeysToFileSystem(new DirectoryInfo(keysPath));

        // On Windows the keys are encrypted with DPAPI. On other platforms they are stored unencrypted, and
        // ASP.NET Core logs a warning about it: protect the directory with file permissions.
        if (OperatingSystem.IsWindows())
            builder.ProtectKeysWithDpapi();

        return services;
    }
}
