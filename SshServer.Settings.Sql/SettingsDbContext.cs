using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Audit;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Webhooks;

namespace SshServer.Settings.Sql;

/// <summary>
/// EF Core model for the server settings (one row) and the users. The entities are the
/// <see cref="ServerSettings"/> and <see cref="User"/> classes from SshServer.Interfaces, so the stored
/// fields are the same as in the LiteDB file. Lists of strings are stored as JSON text columns
/// (EF Core primitive collections), which works on SQLite and on SQL Server. The permissions and path filters of a
/// user are JSON text columns too, with the permission flags as names (<c>{"/":"All","/in":"Upload"}</c>). The audit
/// log (<see cref="AuditEntry"/>), the webhooks with their outbox (<see cref="Webhook"/>, <see cref="WebhookDelivery"/>),
/// the administrators (<see cref="Admin"/>) and the scope roles (<see cref="Role"/>, referenced by
/// <see cref="User.RoleId"/> and <see cref="Admin.ScopeRoleId"/>) are in the same database.
/// </summary>
public class SettingsDbContext : DbContext
{
    public SettingsDbContext(DbContextOptions<SettingsDbContext> options) : base(options)
    {
    }

    public DbSet<ServerSettings> ServerSettings => Set<ServerSettings>();
    public DbSet<User> Users => Set<User>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<Webhook> Webhooks => Set<Webhook>();
    public DbSet<WebhookDelivery> WebhookDeliveries => Set<WebhookDelivery>();
    public DbSet<Admin> Admins => Set<Admin>();
    public DbSet<Role> Roles => Set<Role>();

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
            // A role in use cannot be removed (AdminAdministrationService checks it first, with a clear message).
            b.HasOne<Role>().WithMany().HasForeignKey(u => u.RoleId).OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<Role>(b =>
        {
            b.ToTable("Roles");
            b.HasKey(r => r.Id);
            var name = b.Property(r => r.Name).IsRequired().HasMaxLength(AdminAdministrationService.MaximumRoleNameLength);
            if (Database.IsSqlite())
                name.UseCollation("NOCASE");
            b.HasIndex(r => r.Name).IsUnique();
            b.Property(r => r.Description).HasMaxLength(1000);
        });

        modelBuilder.Entity<Admin>(b =>
        {
            b.ToTable("Admins");
            b.HasKey(a => a.Id);
            var username = b.Property(a => a.Username).IsRequired().HasMaxLength(256);
            if (Database.IsSqlite())
                username.UseCollation("NOCASE");
            b.HasIndex(a => a.Username).IsUnique();
            b.Property(a => a.PasswordHash).IsRequired();
            b.Property(a => a.Status).HasConversion<string>().HasMaxLength(16);
            b.Property(a => a.Email).HasMaxLength(AdminAdministrationService.MaximumEmailLength);
            // The flags as names ("ManageUsers, ViewAudit"), readable in the database and stable when flags are added.
            b.Property(a => a.Permissions).HasConversion<string>().HasMaxLength(512);
            b.PrimitiveCollection(a => a.AllowedIps).IsRequired(false);
            b.HasOne<Role>().WithMany().HasForeignKey(a => a.ScopeRoleId).OnDelete(DeleteBehavior.Restrict);
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

        modelBuilder.Entity<Webhook>(b =>
        {
            b.ToTable("Webhooks");
            b.HasKey(w => w.Id);
            var name = b.Property(w => w.Name).IsRequired().HasMaxLength(100);
            if (Database.IsSqlite())
                name.UseCollation("NOCASE");
            b.HasIndex(w => w.Name).IsUnique();
            b.Property(w => w.Url).IsRequired().HasMaxLength(2048);
            b.Property(w => w.Method).IsRequired().HasMaxLength(8);
            b.Property(w => w.ProtectedSecret).IsRequired(false);
            b.Property(w => w.PathGlob).IsRequired(false).HasMaxLength(1024);
            b.Property(w => w.Headers).IsRequired().HasConversion(
                v => ToJson(v), v => FromJson<Dictionary<string, string>>(v), JsonComparer<Dictionary<string, string>>());
            b.PrimitiveCollection(w => w.EventTypes).IsRequired();
            b.PrimitiveCollection(w => w.Users).IsRequired();
        });

        modelBuilder.Entity<WebhookDelivery>(b =>
        {
            b.ToTable("WebhookDeliveries");
            b.HasKey(d => d.Id);
            b.HasOne<Webhook>().WithMany().HasForeignKey(d => d.WebhookId).OnDelete(DeleteBehavior.Cascade);
            b.Property(d => d.EventType).IsRequired().HasMaxLength(64);
            b.Property(d => d.Payload).IsRequired();
            b.Property(d => d.Status).IsRequired().HasConversion<string>().HasMaxLength(16);
            b.Property(d => d.LeaseOwner).HasMaxLength(128);
            b.HasIndex(d => d.DeliveryId).IsUnique();
            b.HasIndex(d => new { d.Status, d.NextAttemptUtc });
            b.HasIndex(d => new { d.WebhookId, d.CreatedUtc });
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
