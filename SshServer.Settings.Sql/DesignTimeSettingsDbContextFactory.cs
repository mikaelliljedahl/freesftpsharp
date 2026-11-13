using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace SshServer.Settings.Sql;

/// <summary>
/// Used only by <c>dotnet ef migrations add</c>. Run from the repository root (<c>dotnet tool restore</c> installs
/// dotnet-ef from dotnet-tools.json):
/// <c>dotnet ef migrations add &lt;Name&gt; --project SshServer.Settings.Sql --output-dir Migrations/Sqlite</c>
/// </summary>
public sealed class DesignTimeSettingsDbContextFactory : IDesignTimeDbContextFactory<SettingsDbContext>
{
    public SettingsDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<SettingsDbContext>()
            .UseSqlite($"Data Source={SettingsStorageOptions.DefaultSqliteFileName}")
            .Options;
        return new SettingsDbContext(options);
    }
}
