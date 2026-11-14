using Microsoft.Extensions.DependencyInjection;
using SshServer.Settings.Sql.Database;

namespace SshServer.Settings.PostgreSql;

public static class PostgreSqlSettingsServiceCollectionExtensions
{
    /// <summary>
    /// Makes PostgreSQL available as the settings database (<c>Settings:Provider</c> = <c>PostgreSQL</c>). It is used only
    /// when it is selected; the default stays SQLite.
    /// </summary>
    public static IServiceCollection AddPostgreSqlSettings(this IServiceCollection services)
        => services.AddSettingsDatabaseProvider<PostgreSqlSettingsDatabaseProvider>();
}
