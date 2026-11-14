using Microsoft.EntityFrameworkCore;
using SshServer.Interfaces.Admins;

namespace SshServer.Settings.Sql.Admins;

/// <summary>
/// <see cref="IAdminStore"/> in the tables Admins and Roles of the settings database. The settings repository creates
/// and migrates the database at the start; this class only reads and writes rows, each call with its own context.
/// Names are unique without case (NOCASE on SQLite).
/// </summary>
public sealed class SqlAdminStore : IAdminStore
{
    private readonly DbContextOptions<SettingsDbContext> _options;

    public SqlAdminStore(DbContextOptions<SettingsDbContext> options)
    {
        _options = options;
    }

    private SettingsDbContext CreateContext() => new(_options);

    public async Task<bool> AnyAdminAsync(CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.Admins.AnyAsync(ct);
    }

    public async Task<IReadOnlyList<Admin>> ListAdminsAsync(CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.Admins.AsNoTracking().OrderBy(a => a.Id).ToListAsync(ct);
    }

    public async Task<Admin?> GetAdminAsync(string username, CancellationToken ct)
    {
        var name = username?.Trim() ?? "";
        await using var db = CreateContext();
        return await db.Admins.AsNoTracking().FirstOrDefaultAsync(a => a.Username == name, ct);
    }

    public async Task<bool> AddAdminAsync(Admin admin, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(admin.Username))
            return false;
        await using var db = CreateContext();
        if (await db.Admins.AnyAsync(a => a.Username == admin.Username, ct))
            return false;
        var stored = admin.Clone();
        stored.Id = 0;
        db.Admins.Add(stored);
        await db.SaveChangesAsync(ct);
        admin.Id = stored.Id;
        return true;
    }

    public async Task<bool> UpdateAdminAsync(Admin admin, CancellationToken ct)
    {
        await using var db = CreateContext();
        var stored = await db.Admins.FirstOrDefaultAsync(a => a.Id == admin.Id, ct);
        if (stored == null)
            return false;
        stored.Username = admin.Username;
        stored.PasswordHash = admin.PasswordHash;
        stored.Status = admin.Status;
        stored.Email = admin.Email;
        stored.Permissions = admin.Permissions;
        stored.AllowedIps = admin.AllowedIps?.ToList();
        stored.ScopeRoleId = admin.ScopeRoleId;
        stored.LastLoginAt = admin.LastLoginAt;
        stored.MustChangePassword = admin.MustChangePassword;
        stored.AuthenticationProvider = admin.AuthenticationProvider;
        await db.SaveChangesAsync(ct);
        return true;
    }

    public async Task<bool> RemoveAdminAsync(int id, CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.Admins.Where(a => a.Id == id).ExecuteDeleteAsync(ct) > 0;
    }

    public async Task<IReadOnlyList<Role>> ListRolesAsync(CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.Roles.AsNoTracking().OrderBy(r => r.Name).ToListAsync(ct);
    }

    public async Task<Role?> GetRoleAsync(int id, CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.Roles.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id, ct);
    }

    public async Task<bool> AddRoleAsync(Role role, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(role.Name))
            return false;
        await using var db = CreateContext();
        if (await db.Roles.AnyAsync(r => r.Name == role.Name, ct))
            return false;
        var stored = role.Clone();
        stored.Id = 0;
        db.Roles.Add(stored);
        await db.SaveChangesAsync(ct);
        role.Id = stored.Id;
        return true;
    }

    public async Task<bool> UpdateRoleAsync(Role role, CancellationToken ct)
    {
        await using var db = CreateContext();
        var stored = await db.Roles.FirstOrDefaultAsync(r => r.Id == role.Id, ct);
        if (stored == null || await db.Roles.AnyAsync(r => r.Id != role.Id && r.Name == role.Name, ct))
            return false;
        stored.Name = role.Name;
        stored.Description = role.Description;
        await db.SaveChangesAsync(ct);
        return true;
    }

    public async Task<bool> RemoveRoleAsync(int id, CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.Roles.Where(r => r.Id == id).ExecuteDeleteAsync(ct) > 0;
    }
}
