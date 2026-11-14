using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Settings.Sql.Database;

namespace SshServer.Settings.Sql.Cluster;

/// <summary>
/// The data protection key ring in the table DataProtectionKeys of the settings database (issue #75,
/// <c>DataProtection:Store</c> = <c>Database</c>), so that every node reads the login cookies and the encrypted secrets
/// (webhooks, storage, TOTP, the token signing key) of the other nodes. The keys are stored as ASP.NET Core writes them
/// (not encrypted on Linux): protect the database like the key directory.
/// </summary>
public sealed class SqlDataProtectionKeyRepository : IXmlRepository
{
    private readonly Func<DbContextOptions<SettingsDbContext>> _options;

    /// <param name="options">The options of the settings database; called at the first use, after the database is migrated.</param>
    public SqlDataProtectionKeyRepository(Func<DbContextOptions<SettingsDbContext>> options)
    {
        _options = options;
    }

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        using var db = new SettingsDbContext(_options());
        return db.DataProtectionKeys.AsNoTracking().OrderBy(k => k.Id).Select(k => k.Xml).ToList()
            .Select(xml => XElement.Parse(xml)).ToList();
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        using var db = new SettingsDbContext(_options());
        db.DataProtectionKeys.Add(new DataProtectionKeyRow
        {
            FriendlyName = friendlyName.Length <= 256 ? friendlyName : friendlyName[..256],
            Xml = element.ToString(SaveOptions.DisableFormatting),
        });
        db.SaveChanges();
    }
}

public static class SettingsDatabaseDataProtectionExtensions
{
    /// <summary>
    /// Keeps the data protection keys in the settings database (a SQL provider; not LiteDB). The repository creates and
    /// migrates the database before the first key is read.
    /// </summary>
    public static IDataProtectionBuilder PersistKeysToSettingsDatabase(this IDataProtectionBuilder builder)
    {
        builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(sp => new ConfigureOptions<KeyManagementOptions>(options =>
            options.XmlRepository = new SqlDataProtectionKeyRepository(() =>
            {
                sp.GetRequiredService<ISettingsRepository>(); // creates and migrates the database
                return sp.GetService<SettingsDatabase>()?.Options
                       ?? throw new InvalidOperationException("DataProtection:Store=Database needs a SQL settings provider (not LiteDb).");
            })));
        return builder;
    }
}
