using Microsoft.EntityFrameworkCore;
using SshServer.Interfaces.Api;

namespace SshServer.Settings.Sql.Api;

/// <summary>
/// <see cref="IApiKeyStore"/> and <see cref="IApiSigningKeyStore"/> in the tables ApiKeys and ApiSigningKeys of the
/// settings database. The settings repository creates and migrates the database at the start; this class only reads and
/// writes rows, each call with its own context.
/// </summary>
public sealed class SqlApiKeyStore : IApiKeyStore, IApiSigningKeyStore
{
    /// <summary>The one row of ApiSigningKeys.</summary>
    private const int SigningKeyId = 1;

    private readonly DbContextOptions<SettingsDbContext> _options;

    public SqlApiKeyStore(DbContextOptions<SettingsDbContext> options)
    {
        _options = options;
    }

    private SettingsDbContext CreateContext() => new(_options);

    public async Task<IReadOnlyList<ApiKey>> ListAsync(int? adminId, CancellationToken ct)
    {
        await using var db = CreateContext();
        var query = db.ApiKeys.AsNoTracking();
        if (adminId is { } id)
            query = query.Where(k => k.AdminId == id);
        return await query.OrderBy(k => k.Id).ToListAsync(ct);
    }

    public async Task<ApiKey?> GetAsync(int id, CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.ApiKeys.AsNoTracking().FirstOrDefaultAsync(k => k.Id == id, ct);
    }

    public async Task<ApiKey?> FindByHashAsync(string keyHash, CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.ApiKeys.AsNoTracking().FirstOrDefaultAsync(k => k.KeyHash == keyHash, ct);
    }

    public async Task<bool> AddAsync(ApiKey key, CancellationToken ct)
    {
        await using var db = CreateContext();
        if (await db.ApiKeys.AnyAsync(k => k.AdminId == key.AdminId && k.Name == key.Name, ct))
            return false;
        var stored = key.Clone();
        stored.Id = 0;
        db.ApiKeys.Add(stored);
        await db.SaveChangesAsync(ct);
        key.Id = stored.Id;
        return true;
    }

    public async Task<bool> RemoveAsync(int id, CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.ApiKeys.Where(k => k.Id == id).ExecuteDeleteAsync(ct) > 0;
    }

    public async Task TouchAsync(int id, DateTime usedAtUtc, CancellationToken ct)
    {
        await using var db = CreateContext();
        await db.ApiKeys.Where(k => k.Id == id).ExecuteUpdateAsync(s => s.SetProperty(k => k.LastUsedAt, usedAtUtc), ct);
    }

    public async Task<string> GetOrAddAsync(Func<string> create, CancellationToken ct)
    {
        await using (var db = CreateContext())
        {
            var stored = await db.ApiSigningKeys.AsNoTracking().FirstOrDefaultAsync(k => k.Id == SigningKeyId, ct);
            if (stored != null)
                return stored.ProtectedKey;
        }

        try
        {
            await using var db = CreateContext();
            db.ApiSigningKeys.Add(new ApiSigningKey { Id = SigningKeyId, ProtectedKey = create(), CreatedAt = DateTime.UtcNow });
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // Another node stored its key first: use that one.
        }

        await using (var db = CreateContext())
            return (await db.ApiSigningKeys.AsNoTracking().FirstAsync(k => k.Id == SigningKeyId, ct)).ProtectedKey;
    }
}

/// <summary>The row of the signing key of the API bearer tokens (encrypted with data protection by the API).</summary>
public sealed class ApiSigningKey
{
    public int Id { get; set; }

    public string ProtectedKey { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }
}
