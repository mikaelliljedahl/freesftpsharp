using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using SshServer.Interfaces;
using SshServer.Interfaces.Audit;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;

namespace SshServer.Settings.Sql;

/// <summary>
/// EF Core model for the server settings (one row) and the users. The entities are the
/// <see cref="ServerSettings"/> and <see cref="User"/> classes from SshServer.Interfaces, so the stored
/// fields are the same as in the LiteDB file. Lists of strings are stored as JSON text columns
/// (EF Core primitive collections), which works on SQLite and on SQL Server. The permissions and path filters of a
/// user are JSON text columns too, with the permission flags as names (<c>{"/":"All","/in":"Upload"}</c>). The audit
/// log (<see cref="AuditEntry"/>) is in the same database.
/// <para>
/// A <see cref="StorageConfig"/> (the storage of a user or of a <see cref="VirtualFolder"/>) is a JSON text column
/// (<c>{"Provider":"s3","Options":"{...}"}</c>); its secrets are already encrypted. The mounts of a user
/// (<see cref="User.VirtualFolders"/>) are the table UserVirtualFolders, owned by the user, with a foreign key to the
/// folder: removing a user or a folder removes its mounts.
/// </para>
/// </summary>
public class SettingsDbContext : DbContext
{
    public SettingsDbContext(DbContextOptions<SettingsDbContext> options) : base(options)
    {
    }

    public DbSet<ServerSettings> ServerSettings => Set<ServerSettings>();
    public DbSet<User> Users => Set<User>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<VirtualFolder> VirtualFolders => Set<VirtualFolder>();

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
            b.Property(u => u.Storage).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<StorageConfig>(v), JsonComparer<StorageConfig>());
            b.OwnsMany(u => u.VirtualFolders, m =>
            {
                m.ToTable("UserVirtualFolders");
                m.WithOwner().HasForeignKey("UserId");
                m.Property<int>("Id");
                m.HasKey("Id");
                m.Property(x => x.MountPath).IsRequired().HasMaxLength(1024);
                m.HasOne<VirtualFolder>().WithMany().HasForeignKey(x => x.VirtualFolderId).OnDelete(DeleteBehavior.Cascade);
                m.HasIndex("UserId", nameof(VirtualFolderMount.MountPath)).IsUnique();
            });
        });

        modelBuilder.Entity<VirtualFolder>(b =>
        {
            b.ToTable("VirtualFolders");
            b.HasKey(f => f.Id);
            var name = b.Property(f => f.Name).IsRequired().HasMaxLength(256);
            if (Database.IsSqlite())
                name.UseCollation("NOCASE");
            b.HasIndex(f => f.Name).IsUnique();
            b.Property(f => f.Description).IsRequired(false);
            b.Property(f => f.Storage).IsRequired().HasConversion(
                v => ToJson(v), v => FromJson<StorageConfig>(v), JsonComparer<StorageConfig>());
        });

        modelBuilder.Entity<AuditEntry>(b =>
        {
            b.ToTable("AuditEntries");
            b.HasKey(a => a.Id);
            b.Property(a => a.Category).IsRequired().HasMaxLength(32);
            b.Property(a => a.Type).IsRequired().HasMaxLength(64);
            b.Property(a => a.Status).IsRequired().HasMaxLength(32);
            b.Property(a => a.Username).HasMaxLength(256);
            b.Property(a => a.Actor).HasMaxLength(256);
            b.Property(a => a.RemoteIp).HasMaxLength(64);
            b.Property(a => a.Protocol).HasMaxLength(32);
            b.Property(a => a.SessionId).HasMaxLength(64);
            b.HasIndex(a => a.TimestampUtc);
            b.HasIndex(a => a.Username);
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
