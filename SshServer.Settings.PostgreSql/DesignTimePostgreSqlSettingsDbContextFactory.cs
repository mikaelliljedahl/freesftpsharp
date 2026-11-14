using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using SshServer.Settings.Sql;

namespace SshServer.Settings.PostgreSql;

/// <summary>
/// Used only by <c>dotnet ef migrations add</c> (no database is opened). From the repository root:
/// <c>dotnet ef migrations add &lt;Name&gt; --project SshServer.Settings.PostgreSql --output-dir Migrations</c>
/// </summary>
public sealed class DesignTimePostgreSqlSettingsDbContextFactory : IDesignTimeDbContextFactory<SettingsDbContext>
{
    public SettingsDbContext CreateDbContext(string[] args)
    {
        var builder = new DbContextOptionsBuilder<SettingsDbContext>();
        new PostgreSqlSettingsDatabaseProvider().Configure(builder, "Host=localhost;Database=freesftpsharp");
        return new SettingsDbContext(builder.Options);
    }
}
