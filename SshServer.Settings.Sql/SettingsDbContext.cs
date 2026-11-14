using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using SshServer.Interfaces;
using SshServer.Interfaces.Permissions;

namespace SshServer.Settings.Sql;

/// <summary>
/// EF Core model for the server settings (one row) and the users. The entities are the
/// <see cref="ServerSettings"/> and <see cref="User"/> classes from SshServer.Interfaces, so the stored
/// fields are the same as in the LiteDB file. Lists of strings are stored as JSON text columns
/// (EF Core primitive collections), which works on SQLite and on SQL Server. The permissions and path filters of a
/// user are JSON text columns too, with the permission flags as names (<c>{"/":"All","/in":"Upload"}</c>).
/// </summary>
public class SettingsDbContext : DbContext
{
    public SettingsDbContext(DbContextOptions<SettingsDbContext> options) : base(options)
    {
    }

    public DbSet<ServerSettings> ServerSettings => Set<ServerSettings>();
    public DbSet<User> Users => Set<User>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ServerSettings>(b =>
        {
            b.ToTable("ServerSettings");
            b.HasKey(s => s.Id);
            b.Property(s => s.ServerRsaKey).IsRequired(false);
            b.Property(s => s.ServerEcdsaKey).IsRequired(false);
            b.Property(s => s.ServerBanner).IsRequired(false);
            b.PrimitiveCollection(s => s.BindToAddress).IsRequired(false);
            b.PrimitiveCollection(s => s.BlacklistedIps).IsRequired(false);
            b.PrimitiveCollection(s => s.WhitelistedIps).IsRequired(false);
        });

        modelBuilder.Entity<User>(b =>
        {
            b.ToTable("Users");
            b.HasKey(u => u.Id);
            var username = b.Property(u => u.Username).IsRequired().HasMaxLength(256);
            // LiteDB compares strings case-insensitively by default, so "Bob" and "bob" were the same user.
            // NOCASE keeps that behaviour on SQLite. Another provider sets its own collation.
            if (Database.IsSqlite())
                username.UseCollation("NOCASE");
            b.HasIndex(u => u.Username).IsUnique();
            b.Property(u => u.UserRootDirectory).IsRequired(false);
            b.Property(u => u.HashedPassword).IsRequired(false);
            b.Property(u => u.RsaPublicKey).IsRequired(false);
            b.PrimitiveCollection(u => u.WhitelistedIps).IsRequired(false);
            b.Property(u => u.Permissions).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<Dictionary<string, FilePermissions>>(v), JsonComparer<Dictionary<string, FilePermissions>>());
            b.Property(u => u.PathFilters).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<Dictionary<string, PathFilter>>(v), JsonComparer<Dictionary<string, PathFilter>>());
        });
    }

    private static readonly JsonSerializerOptions JsonOptions = new() { Converters = { new JsonStringEnumConverter() } };

    private static string ToJson<T>(T value) => JsonSerializer.Serialize(value, JsonOptions);

    private static T FromJson<T>(string json) => JsonSerializer.Deserialize<T>(json, JsonOptions)!;

    /// <summary>Compares by the JSON text, so a change inside a dictionary or a filter is saved too.</summary>
    private static ValueComparer<T?> JsonComparer<T>() where T : class => new(
        (a, b) => ToJson(a) == ToJson(b),
        v => ToJson(v).GetHashCode(),
        v => v == null ? null : FromJson<T>(ToJson(v)));
}
