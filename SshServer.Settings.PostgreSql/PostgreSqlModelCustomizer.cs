using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using SshServer.Settings.Sql;

namespace SshServer.Settings.PostgreSql;

/// <summary>
/// The PostgreSQL rules of the settings model, after <see cref="SettingsDbContext.OnModelCreating"/>:
/// <list type="bullet">
/// <item>A column marked <see cref="SettingsDbContext.CaseInsensitiveAnnotation"/> is <c>citext</c>, so "Bob" and "bob"
/// are the same name, like the NOCASE collation of SQLite.</item>
/// <item><c>timestamp with time zone</c> takes only UTC: a <see cref="DateTime"/> without a kind is stored as UTC (SQLite
/// keeps the value as it is too), a <see cref="DateTimeOffset"/> is stored at offset 0.</item>
/// <item>The column names in a check constraint are quoted (PostgreSQL folds unquoted names to lower case).</item>
/// </list>
/// </summary>
public sealed class PostgreSqlModelCustomizer : RelationalModelCustomizer
{
    private static readonly ValueConverter<DateTime, DateTime> UtcDateTime = new(
        v => v.Kind == DateTimeKind.Utc ? v : DateTime.SpecifyKind(v, DateTimeKind.Utc),
        v => DateTime.SpecifyKind(v, DateTimeKind.Utc));

    private static readonly ValueConverter<DateTimeOffset, DateTimeOffset> UtcDateTimeOffset = new(
        v => v.ToUniversalTime(),
        v => v);

    public PostgreSqlModelCustomizer(ModelCustomizerDependencies dependencies) : base(dependencies)
    {
    }

    public override void Customize(ModelBuilder modelBuilder, DbContext context)
    {
        base.Customize(modelBuilder, context);
        modelBuilder.HasPostgresExtension("citext");

        foreach (var entity in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var property in entity.GetProperties())
            {
                if (property.FindAnnotation(SettingsDbContext.CaseInsensitiveAnnotation)?.Value is true)
                    property.SetColumnType("citext");
                var type = Nullable.GetUnderlyingType(property.ClrType) ?? property.ClrType;
                if (type == typeof(DateTime) && property.GetValueConverter() == null)
                    property.SetValueConverter(UtcDateTime);
                else if (type == typeof(DateTimeOffset) && property.GetValueConverter() == null)
                    property.SetValueConverter(UtcDateTimeOffset);
            }

            foreach (var check in entity.GetCheckConstraints().ToList())
            {
                var sql = check.Sql;
                foreach (var property in entity.GetProperties())
                {
                    var column = property.GetColumnName();
                    sql = Regex.Replace(sql, $"(?<![\"\\w]){Regex.Escape(column)}(?![\"\\w])", $"\"{column}\"");
                }
                var name = check.ModelName;
                entity.RemoveCheckConstraint(name);
                entity.AddCheckConstraint(name, sql);
            }
        }
    }
}
