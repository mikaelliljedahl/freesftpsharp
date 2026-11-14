using System.Net;
using Microsoft.EntityFrameworkCore;
using SshServer.Interfaces;

namespace SshServer.Settings.Sql.Cluster;

/// <summary><see cref="IIpBanStore"/> in the table BannedIps of the settings database (issue #75). Each call has its own context.</summary>
public sealed class SqlIpBanStore : IIpBanStore
{
    private readonly DbContextOptions<SettingsDbContext> _options;

    public SqlIpBanStore(DbContextOptions<SettingsDbContext> options)
    {
        _options = options;
    }

    public async Task AddAsync(IpBan ban, CancellationToken ct)
    {
        await using var db = new SettingsDbContext(_options);
        var address = ban.Address.ToString();
        var row = await db.BannedIps.FirstOrDefaultAsync(r => r.Address == address, ct);
        if (row == null)
            db.BannedIps.Add(row = new BannedIpRow { Address = address });
        row.BannedUtc = ban.BannedAt.UtcDateTime;
        row.ExpiresUtc = ban.ExpiresAt.UtcDateTime;
        row.FailedAttempts = ban.FailedAttempts;
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // Another node banned the address at the same time: its ban is as good as this one.
        }
    }

    public async Task<IReadOnlyList<IpBan>> ListActiveAsync(DateTimeOffset now, CancellationToken ct)
    {
        await using var db = new SettingsDbContext(_options);
        var nowUtc = now.UtcDateTime;
        var rows = await db.BannedIps.AsNoTracking().Where(r => r.ExpiresUtc > nowUtc).ToListAsync(ct);
        return rows
            .Where(r => IPAddress.TryParse(r.Address, out _))
            .Select(r => new IpBan(IPAddress.Parse(r.Address), Utc(r.BannedUtc), Utc(r.ExpiresUtc), r.FailedAttempts))
            .ToList();
    }

    public async Task RemoveAsync(IPAddress address, CancellationToken ct)
    {
        await using var db = new SettingsDbContext(_options);
        var text = address.ToString();
        await db.BannedIps.Where(r => r.Address == text).ExecuteDeleteAsync(ct);
    }

    public async Task<int> RemoveExpiredAsync(DateTimeOffset now, CancellationToken ct)
    {
        await using var db = new SettingsDbContext(_options);
        var nowUtc = now.UtcDateTime;
        return await db.BannedIps.Where(r => r.ExpiresUtc <= nowUtc).ExecuteDeleteAsync(ct);
    }

    private static DateTimeOffset Utc(DateTime value) => new(DateTime.SpecifyKind(value, DateTimeKind.Utc));
}
