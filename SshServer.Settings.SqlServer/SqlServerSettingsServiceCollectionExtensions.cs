using Microsoft.Extensions.DependencyInjection;
using SshServer.Settings.Sql.Database;

namespace SshServer.Settings.SqlServer;

public static class SqlServerSettingsServiceCollectionExtensions
{
    /// <summary>
    /// Makes SQL Server available as the settings database (<c>Settings:Provider</c> = <c>SqlServer</c>). It is used only
    /// when it is selected; the default stays SQLite.
    /// </summary>
    public static IServiceCollection AddSqlServerSettings(this IServiceCollection services)
        => services.AddSettingsDatabaseProvider<SqlServerSettingsDatabaseProvider>();
}
