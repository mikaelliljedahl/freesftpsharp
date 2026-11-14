using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using SshServer.Settings.Sql;

namespace SshServer.Settings.SqlServer;

/// <summary>
/// Used only by <c>dotnet ef migrations add</c> (no database is opened). From the repository root:
/// <c>dotnet ef migrations add &lt;Name&gt; --project SshServer.Settings.SqlServer --output-dir Migrations</c>
/// </summary>
public sealed class DesignTimeSqlServerSettingsDbContextFactory : IDesignTimeDbContextFactory<SettingsDbContext>
{
    public SettingsDbContext CreateDbContext(string[] args)
    {
        var builder = new DbContextOptionsBuilder<SettingsDbContext>();
        new SqlServerSettingsDatabaseProvider().Configure(builder, "Server=localhost;Database=freesftpsharp;TrustServerCertificate=True");
        return new SettingsDbContext(builder.Options);
    }
}
