using Microsoft.EntityFrameworkCore;

namespace SshServer.Settings.Sql.Database;

/// <summary>
/// An EF Core database for the settings (issue #75): SQLite (built in, the default), PostgreSQL
/// (<c>SshServer.Settings.PostgreSql</c>, <c>AddPostgreSqlSettings()</c>) or SQL Server (<c>SshServer.Settings.SqlServer</c>,
/// <c>AddSqlServerSettings()</c>). <c>Settings:Provider</c> selects one by its <see cref="Name"/> (without case), in
/// <see cref="SettingsDatabase.Create"/> only. Each provider has its own migrations, in its own assembly; the model is the
/// same (<see cref="SettingsDbContext"/>), with JSON text columns.
/// </summary>
public interface ISettingsDatabaseProvider
{
    /// <summary>The value of <c>Settings:Provider</c>, for example "PostgreSQL".</summary>
    string Name { get; }

    /// <summary>The connection string to use for the configured one (<c>ConnectionStrings:Settings</c>, null when not set).</summary>
    string ResolveConnectionString(string? configured, string baseDirectory);

    /// <summary>Sets the EF Core provider, its migrations assembly and its model rules on <paramref name="builder"/>.</summary>
    void Configure(DbContextOptionsBuilder<SettingsDbContext> builder, string connectionString);
}
