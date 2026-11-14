using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Audit;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.Webhooks;
using SshServer.Settings.Sql.Quotas;
using SshServer.Settings.Sql.TwoFactor;

namespace SshServer.Settings.Sql;

/// <summary>
/// EF Core model for the server settings (one row) and the users. The entities are the
/// <see cref="ServerSettings"/> and <see cref="User"/> classes from SshServer.Interfaces, so the stored
/// fields are the same as in the LiteDB file. Lists of strings are stored as JSON text columns
/// (EF Core primitive collections), which works on SQLite and on SQL Server. The permissions and path filters of a
/// user are JSON text columns too, with the permission flags as names (<c>{"/":"All","/in":"Upload"}</c>), and so are
/// the public keys and the required login steps (issue #58). The allowed login methods are a text column with the flag
/// names (<c>All</c>, <c>Password, PublicKey</c>). The audit
/// log (<see cref="AuditEntry"/>), the webhooks with their outbox (<see cref="Webhook"/>, <see cref="WebhookDelivery"/>),
/// the administrators (<see cref="Admin"/>), the scope roles (<see cref="Role"/>, referenced by
/// <see cref="User.RoleId"/> and <see cref="Admin.ScopeRoleId"/>) and the event rules with their runs
/// (<see cref="EventRule"/>, <see cref="EventRuleRun"/>; conditions and actions as JSON text columns) are in the same database.
/// <para>
/// A <see cref="StorageConfig"/> (the storage of a user or of a <see cref="VirtualFolder"/>) is a JSON text column
/// (<c>{"Provider":"s3","Options":"{...}"}</c>); its secrets are already encrypted. The mounts of a user
/// (<see cref="User.VirtualFolders"/>) are the table UserVirtualFolders, owned by the user, with a foreign key to the
/// folder: removing a user or a folder removes its mounts.
/// </para>
/// <para>
/// The groups (issue #61, <see cref="Group"/>) are the table Groups, with the same JSON columns as a user and their
/// mounts in GroupVirtualFolders. <see cref="User.PrimaryGroupId"/> is a foreign key (a group with members cannot be
/// removed); <see cref="User.SecondaryGroupIds"/> is a JSON list of ids.
/// </para>
/// <para>
/// The quotas of a user (<see cref="User.DiskQuota"/>, <see cref="User.TransferQuota"/>, <see cref="User.Bandwidth"/>)
/// and of a group, and of a mount (<see cref="VirtualFolderMount.Quota"/>), are JSON text columns, null for none (issue #62). The counters are
/// the table QuotaUsages, one row per scope (<see cref="QuotaUsageRow"/>), changed by increments.
/// </para>
/// </summary>
public class SettingsDbContext : DbContext
{
    /// <summary>
    /// The old single key of a user (a base64 CSP blob, before issue #58), a shadow property of the column
    /// "RsaPublicKey". <see cref="SqlSettingsRepository"/> converts it to an entry of <see cref="User.PublicKeys"/> at
    /// start and clears it; nothing else reads it.
    /// </summary>
    internal const string LegacyRsaPublicKey = "RsaPublicKey";

    public SettingsDbContext(DbContextOptions<SettingsDbContext> options) : base(options)
    {
    }

    public DbSet<ServerSettings> ServerSettings => Set<ServerSettings>();
    public DbSet<User> Users => Set<User>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<VirtualFolder> VirtualFolders => Set<VirtualFolder>();
    public DbSet<Webhook> Webhooks => Set<Webhook>();
    public DbSet<WebhookDelivery> WebhookDeliveries => Set<WebhookDelivery>();
    public DbSet<Admin> Admins => Set<Admin>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<Group> Groups => Set<Group>();
    public DbSet<TwoFactorRecord> TwoFactorEnrolments => Set<TwoFactorRecord>();
    public DbSet<EventRule> EventRules => Set<EventRule>();
    public DbSet<EventRuleRun> EventRuleRuns => Set<EventRuleRun>();
    public DbSet<QuotaUsageRow> QuotaUsages => Set<QuotaUsageRow>();

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
            b.Property<string?>(LegacyRsaPublicKey).IsRequired(false);
            b.Property(u => u.PublicKeys).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<List<PublicKeyEntry>>(v), JsonComparer<List<PublicKeyEntry>>());
            b.Property(u => u.AllowedAuthMethods).IsRequired().HasMaxLength(128).HasConversion<string>();
            b.Property(u => u.RequireAllOf).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<List<AuthMethods>>(v), JsonComparer<List<AuthMethods>>());
            b.PrimitiveCollection(u => u.WhitelistedIps).IsRequired(false);
            b.Property(u => u.Permissions).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<Dictionary<string, FilePermissions>>(v), JsonComparer<Dictionary<string, FilePermissions>>());
            b.Property(u => u.PathFilters).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<Dictionary<string, PathFilter>>(v), JsonComparer<Dictionary<string, PathFilter>>());
            b.Property(u => u.Storage).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<StorageConfig>(v), JsonComparer<StorageConfig>());
            b.Property(u => u.DiskQuota).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<DiskQuota>(v), JsonComparer<DiskQuota>());
            b.Property(u => u.TransferQuota).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<TransferQuota>(v), JsonComparer<TransferQuota>());
            b.Property(u => u.Bandwidth).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<BandwidthLimit>(v), JsonComparer<BandwidthLimit>());
            // A role in use cannot be removed (AdminAdministrationService checks it first, with a clear message).
            b.HasOne<Role>().WithMany().HasForeignKey(u => u.RoleId).OnDelete(DeleteBehavior.Restrict);
            b.Property(u => u.Description).IsRequired(false).HasMaxLength(1000);
            // The migration gives the existing users "Enabled".
            b.Property(u => u.Status).HasConversion<string>().HasMaxLength(16);
            // A group with members cannot be removed (GroupService checks it first, with a clear message).
            b.HasOne<Group>().WithMany().HasForeignKey(u => u.PrimaryGroupId).OnDelete(DeleteBehavior.Restrict);
            b.PrimitiveCollection(u => u.SecondaryGroupIds).IsRequired();
            // The authentication provider that owns the user (#64); null: the local database.
            b.Property(u => u.AuthenticationProvider).IsRequired(false).HasMaxLength(64);
            b.OwnsMany(u => u.VirtualFolders, m =>
            {
                m.ToTable("UserVirtualFolders");
                m.WithOwner().HasForeignKey("UserId");
                m.Property<int>("Id");
                m.HasKey("Id");
                m.Property(x => x.MountPath).IsRequired().HasMaxLength(1024);
                m.Property(x => x.Quota).IsRequired(false).HasConversion(
                    v => ToJson(v), v => FromJson<DiskQuota>(v), JsonComparer<DiskQuota>());
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

        modelBuilder.Entity<Group>(b =>
        {
            b.ToTable("Groups");
            b.HasKey(g => g.Id);
            var name = b.Property(g => g.Name).IsRequired().HasMaxLength(GroupService.MaximumNameLength);
            if (Database.IsSqlite())
                name.UseCollation("NOCASE");
            b.HasIndex(g => g.Name).IsUnique();
            b.Property(g => g.Description).IsRequired(false).HasMaxLength(1000);
            b.Property(g => g.Permissions).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<Dictionary<string, FilePermissions>>(v), JsonComparer<Dictionary<string, FilePermissions>>());
            b.Property(g => g.PathFilters).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<Dictionary<string, PathFilter>>(v), JsonComparer<Dictionary<string, PathFilter>>());
            b.Property(g => g.Storage).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<StorageConfig>(v), JsonComparer<StorageConfig>());
            b.Property(g => g.AllowedAuthMethods).IsRequired(false).HasMaxLength(128).HasConversion<string>();
            b.PrimitiveCollection(g => g.AllowedIps).IsRequired(false);
            b.HasOne<Role>().WithMany().HasForeignKey(g => g.RoleId).OnDelete(DeleteBehavior.Restrict);
            b.OwnsMany(g => g.VirtualFolders, m =>
            {
                m.ToTable("GroupVirtualFolders");
                m.WithOwner().HasForeignKey("GroupId");
                m.Property<int>("Id");
                m.HasKey("Id");
                m.Property(x => x.MountPath).IsRequired().HasMaxLength(1024);
                m.HasOne<VirtualFolder>().WithMany().HasForeignKey(x => x.VirtualFolderId).OnDelete(DeleteBehavior.Cascade);
                m.HasIndex("GroupId", nameof(VirtualFolderMount.MountPath)).IsUnique();
                m.Property(x => x.Quota).IsRequired(false).HasConversion(
                    v => ToJson(v), v => FromJson<DiskQuota>(v), JsonComparer<DiskQuota>());
            });
            b.Property(g => g.DiskQuota).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<DiskQuota>(v), JsonComparer<DiskQuota>());
            b.Property(g => g.TransferQuota).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<TransferQuota>(v), JsonComparer<TransferQuota>());
            b.Property(g => g.Bandwidth).IsRequired(false).HasConversion(
                v => ToJson(v), v => FromJson<BandwidthLimit>(v), JsonComparer<BandwidthLimit>());
        });

        modelBuilder.Entity<QuotaUsageRow>(b =>
        {
            b.ToTable("QuotaUsages");
            b.HasKey(q => q.Scope);
            b.Property(q => q.Scope).HasMaxLength(300);
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

        modelBuilder.Entity<TwoFactorRecord>(b =>
        {
            // Exactly one owner: a user or an administrator.
            b.ToTable("TwoFactorEnrolments", t => t.HasCheckConstraint("CK_TwoFactorEnrolments_Owner",
                "(UserId IS NULL AND AdminId IS NOT NULL) OR (UserId IS NOT NULL AND AdminId IS NULL)"));
            b.HasKey(r => r.Id);
            b.HasOne<User>().WithMany().HasForeignKey(r => r.UserId).OnDelete(DeleteBehavior.Cascade);
            b.HasOne<Admin>().WithMany().HasForeignKey(r => r.AdminId).OnDelete(DeleteBehavior.Cascade);
            b.HasIndex(r => r.UserId).IsUnique();
            b.HasIndex(r => r.AdminId).IsUnique();
            b.Property(r => r.ProtectedSecret).IsRequired().HasMaxLength(1024);
            b.PrimitiveCollection(r => r.RecoveryCodeHashes).IsRequired();
            b.Property(r => r.Version).IsConcurrencyToken();
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

        modelBuilder.Entity<EventRule>(b =>
        {
            b.ToTable("EventRules");
            b.HasKey(r => r.Id);
            var name = b.Property(r => r.Name).IsRequired().HasMaxLength(EventRule.MaxNameLength);
            if (Database.IsSqlite())
                name.UseCollation("NOCASE");
            b.HasIndex(r => r.Name).IsUnique();
            b.Property(r => r.Description).HasMaxLength(1000);
            b.Property(r => r.Trigger).IsRequired().HasConversion<string>().HasMaxLength(16);
            b.PrimitiveCollection(r => r.EventTypes).IsRequired();
            b.Property(r => r.CronExpression).HasMaxLength(256);
            b.Property(r => r.TimeZone).HasMaxLength(128);
            b.Property(r => r.Conditions).IsRequired().HasConversion(
                v => ToJson(v), v => FromJson<EventRuleConditions>(v), JsonComparer<EventRuleConditions>());
            b.Property(r => r.Actions).IsRequired().HasConversion(
                v => ToJson(v), v => FromJson<List<EventRuleAction>>(v), JsonComparer<List<EventRuleAction>>());
        });

        modelBuilder.Entity<EventRuleRun>(b =>
        {
            b.ToTable("EventRuleRuns");
            b.HasKey(r => r.Id);
            b.HasOne<EventRule>().WithMany().HasForeignKey(r => r.RuleId).OnDelete(DeleteBehavior.Cascade);
            b.Property(r => r.Status).IsRequired().HasConversion<string>().HasMaxLength(16);
            b.Property(r => r.Trigger).IsRequired().HasMaxLength(64);
            b.Property(r => r.Username).HasMaxLength(256);
            b.Property(r => r.Message).IsRequired().HasMaxLength(EventRuleRun.MaxMessageLength);
            b.HasIndex(r => new { r.RuleId, r.StartedUtc });
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
