using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace SshServer.Settings.Sql.Database;

/// <summary>
/// A step of a provider that runs after the start migrated the settings database (<see cref="SqlSettingsRepository"/>),
/// set in <see cref="ISettingsDatabaseProvider.Configure"/>. PostgreSQL reloads its types there: a node that connected
/// before another node created the citext extension does not know the type otherwise (#149).
/// </summary>
public sealed class AfterMigrationExtension : IDbContextOptionsExtension
{
    public AfterMigrationExtension(Action<DbContext> afterMigration)
    {
        AfterMigration = afterMigration;
    }

    public Action<DbContext> AfterMigration { get; }

    public DbContextOptionsExtensionInfo Info => new ExtensionInfo(this);

    public void ApplyServices(IServiceCollection services)
    {
    }

    public void Validate(IDbContextOptions options)
    {
    }

    /// <summary>Adds the step to <paramref name="builder"/>.</summary>
    public static void Add(DbContextOptionsBuilder builder, Action<DbContext> afterMigration)
        => ((IDbContextOptionsBuilderInfrastructure)builder).AddOrUpdateExtension(new AfterMigrationExtension(afterMigration));

    /// <summary>Runs the step of the options of <paramref name="db"/>, if there is one.</summary>
    internal static void Run(DbContext db)
        => db.GetService<IDbContextOptions>().FindExtension<AfterMigrationExtension>()?.AfterMigration(db);

    private sealed class ExtensionInfo(IDbContextOptionsExtension extension) : DbContextOptionsExtensionInfo(extension)
    {
        public override bool IsDatabaseProvider => false;

        public override string LogFragment => "";

        public override int GetServiceProviderHashCode() => 0;

        public override bool ShouldUseSameServiceProvider(DbContextOptionsExtensionInfo other) => other is ExtensionInfo;

        public override void PopulateDebugInfo(IDictionary<string, string> debugInfo)
        {
        }
    }
}
