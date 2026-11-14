using Microsoft.EntityFrameworkCore;
using SshServer.Interfaces.Shares;

namespace SshServer.Settings.Sql.Shares;

/// <summary>
/// <see cref="IShareStore"/> in the table Shares of the settings database (#70), with a foreign key to the owner: removing
/// the user removes its shares. The settings repository creates and migrates the database at the start; this class only
/// reads and writes rows, each call with its own context.
/// </summary>
public sealed class SqlShareStore : IShareStore
{
    private readonly DbContextOptions<SettingsDbContext> _options;

    public SqlShareStore(DbContextOptions<SettingsDbContext> options)
    {
        _options = options;
    }

    private SettingsDbContext CreateContext() => new(_options);

    public async Task<IReadOnlyList<Share>> ListAsync(int? userId, CancellationToken ct)
    {
        await using var db = CreateContext();
        var query = db.Shares.AsNoTracking();
        if (userId is { } id)
            query = query.Where(s => s.UserId == id);
        // SQLite cannot order by a DateTime column in SQL: order the (few) rows here.
        return (await query.ToListAsync(ct)).OrderByDescending(s => s.CreatedAt).ToList();
    }

    public async Task<Share?> GetAsync(string id, CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.Shares.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, ct);
    }

    public async Task AddAsync(Share share, CancellationToken ct)
    {
        await using var db = CreateContext();
        db.Shares.Add(share.Clone());
        await db.SaveChangesAsync(ct);
    }

    public async Task<bool> RemoveAsync(string id, CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.Shares.Where(s => s.Id == id).ExecuteDeleteAsync(ct) > 0;
    }

    public async Task<bool> TryUseAsync(string id, DateTime usedAtUtc, CancellationToken ct)
    {
        await using var db = CreateContext();
        // One conditional UPDATE: the check of the limit and the count are one step, also with several nodes.
        var changed = await db.Shares
            .Where(s => s.Id == id && (s.MaxUses <= 0 || s.UsedCount < s.MaxUses))
            .ExecuteUpdateAsync(u => u.SetProperty(s => s.UsedCount, s => s.UsedCount + 1).SetProperty(s => s.LastUsedAt, usedAtUtc), ct);
        return changed > 0;
    }
}
