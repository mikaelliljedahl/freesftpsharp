using Microsoft.EntityFrameworkCore;
using SshServer.Interfaces.Webhooks;

namespace SshServer.Settings.Sql.Webhooks;

/// <summary>
/// <see cref="IWebhookStore"/> in the tables Webhooks and WebhookDeliveries of the settings database. The settings
/// repository creates and migrates the database at the start; this class only reads and writes rows, each call with its
/// own context. A claim of a delivery is one conditional UPDATE per row (a lease column), so several nodes (#75) can
/// share the outbox without a lock.
/// </summary>
public sealed class SqlWebhookStore : IWebhookStore
{
    private readonly DbContextOptions<SettingsDbContext> _options;

    public SqlWebhookStore(DbContextOptions<SettingsDbContext> options)
    {
        _options = options;
    }

    public bool IsEnabled => true;

    private SettingsDbContext CreateContext() => new(_options);

    public async Task<IReadOnlyList<Webhook>> ListAsync(CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.Webhooks.AsNoTracking().OrderBy(w => w.Name).ToListAsync(ct);
    }

    public async Task<Webhook?> GetAsync(int id, CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.Webhooks.AsNoTracking().FirstOrDefaultAsync(w => w.Id == id, ct);
    }

    public async Task<bool> AddAsync(Webhook webhook, CancellationToken ct)
    {
        await using var db = CreateContext();
        if (await NameIsUsedAsync(db, webhook.Name, exceptId: null, ct))
            return false;
        var row = Copy(webhook, new Webhook());
        db.Webhooks.Add(row);
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            return false; // the unique name, added at the same time
        }
        webhook.Id = row.Id;
        return true;
    }

    public async Task<bool> UpdateAsync(Webhook webhook, CancellationToken ct)
    {
        await using var db = CreateContext();
        var row = await db.Webhooks.FirstOrDefaultAsync(w => w.Id == webhook.Id, ct);
        if (row == null || await NameIsUsedAsync(db, webhook.Name, exceptId: webhook.Id, ct))
            return false;
        Copy(webhook, row);
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            return false;
        }
        return true;
    }

    public async Task<bool> RemoveAsync(int id, CancellationToken ct)
    {
        await using var db = CreateContext();
        // The deliveries first: the foreign key cascades too, but SQLite needs foreign keys on for it.
        await db.WebhookDeliveries.Where(d => d.WebhookId == id).ExecuteDeleteAsync(ct);
        return await db.Webhooks.Where(w => w.Id == id).ExecuteDeleteAsync(ct) > 0;
    }

    public async Task AddDeliveriesAsync(IReadOnlyList<WebhookDelivery> deliveries, CancellationToken ct)
    {
        if (deliveries.Count == 0)
            return;
        await using var db = CreateContext();
        foreach (var delivery in deliveries)
        {
            delivery.Id = 0;
            db.WebhookDeliveries.Add(delivery);
        }
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<WebhookDelivery>> ClaimDueAsync(string owner, DateTime nowUtc, DateTime leaseUntilUtc, int max, CancellationToken ct)
    {
        if (max <= 0)
            return [];
        await using var db = CreateContext();
        var candidates = await Due(db, nowUtc)
            .OrderBy(d => d.NextAttemptUtc).ThenBy(d => d.Id)
            .Select(d => d.Id)
            .Take(max)
            .ToListAsync(ct);

        var claimed = new List<long>();
        foreach (var id in candidates)
        {
            // The condition again: another node can have taken it since the select.
            var updated = await Due(db, nowUtc).Where(d => d.Id == id)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(d => d.LeaseOwner, owner)
                    .SetProperty(d => d.LeaseUntilUtc, leaseUntilUtc), ct);
            if (updated == 1)
                claimed.Add(id);
        }
        if (claimed.Count == 0)
            return [];
        return await db.WebhookDeliveries.AsNoTracking().Where(d => claimed.Contains(d.Id)).OrderBy(d => d.NextAttemptUtc).ToListAsync(ct);
    }

    private static IQueryable<WebhookDelivery> Due(SettingsDbContext db, DateTime nowUtc)
        => db.WebhookDeliveries.Where(d => d.Status == WebhookDeliveryStatus.Pending && d.NextAttemptUtc != null && d.NextAttemptUtc <= nowUtc
            && (d.LeaseUntilUtc == null || d.LeaseUntilUtc < nowUtc));

    public async Task SaveAttemptAsync(WebhookDelivery delivery, CancellationToken ct)
    {
        await using var db = CreateContext();
        await db.WebhookDeliveries.Where(d => d.Id == delivery.Id)
            .ExecuteUpdateAsync(s => s
                .SetProperty(d => d.Status, delivery.Status)
                .SetProperty(d => d.Attempts, delivery.Attempts)
                .SetProperty(d => d.NextAttemptUtc, delivery.NextAttemptUtc)
                .SetProperty(d => d.LastAttemptUtc, delivery.LastAttemptUtc)
                .SetProperty(d => d.LastStatusCode, delivery.LastStatusCode)
                .SetProperty(d => d.LastError, delivery.LastError)
                .SetProperty(d => d.ResponseExcerpt, delivery.ResponseExcerpt)
                .SetProperty(d => d.LeaseOwner, (string?)null)
                .SetProperty(d => d.LeaseUntilUtc, (DateTime?)null), ct);
    }

    public async Task ReleaseAsync(long id, CancellationToken ct)
    {
        await using var db = CreateContext();
        await db.WebhookDeliveries.Where(d => d.Id == id)
            .ExecuteUpdateAsync(s => s
                .SetProperty(d => d.LeaseOwner, (string?)null)
                .SetProperty(d => d.LeaseUntilUtc, (DateTime?)null), ct);
    }

    public async Task<IReadOnlyList<WebhookDelivery>> ListDeliveriesAsync(int webhookId, int take, CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.WebhookDeliveries.AsNoTracking()
            .Where(d => d.WebhookId == webhookId)
            .OrderByDescending(d => d.CreatedUtc).ThenByDescending(d => d.Id)
            .Take(Math.Clamp(take, 0, 1000))
            .ToListAsync(ct);
    }

    public async Task<bool> RedeliverAsync(long id, DateTime nowUtc, CancellationToken ct)
    {
        await using var db = CreateContext();
        var updated = await db.WebhookDeliveries
            .Where(d => d.Id == id && !d.Sync && (d.LeaseUntilUtc == null || d.LeaseUntilUtc < nowUtc))
            .ExecuteUpdateAsync(s => s
                .SetProperty(d => d.Status, WebhookDeliveryStatus.Pending)
                .SetProperty(d => d.Attempts, 0)
                .SetProperty(d => d.NextAttemptUtc, nowUtc)
                .SetProperty(d => d.LeaseOwner, (string?)null)
                .SetProperty(d => d.LeaseUntilUtc, (DateTime?)null), ct);
        return updated == 1;
    }

    public async Task<int> DeleteFinishedOlderThanAsync(DateTime cutoffUtc, CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.WebhookDeliveries
            .Where(d => d.Status != WebhookDeliveryStatus.Pending && d.CreatedUtc < cutoffUtc)
            .ExecuteDeleteAsync(ct);
    }

    private static async Task<bool> NameIsUsedAsync(SettingsDbContext db, string name, int? exceptId, CancellationToken ct)
    {
        var lower = name.Trim().ToLowerInvariant();
        return await db.Webhooks.AnyAsync(w => w.Name.ToLower() == lower && (exceptId == null || w.Id != exceptId), ct);
    }

    private static Webhook Copy(Webhook from, Webhook to)
    {
        to.Name = from.Name;
        to.Url = from.Url;
        to.Method = from.Method;
        to.ProtectedSecret = from.ProtectedSecret;
        to.Headers = new Dictionary<string, string>(from.Headers);
        to.EventTypes = [.. from.EventTypes];
        to.Users = [.. from.Users];
        to.PathGlob = from.PathGlob;
        to.Sync = from.Sync;
        to.FailOpen = from.FailOpen;
        to.TimeoutSeconds = from.TimeoutSeconds;
        to.Enabled = from.Enabled;
        to.OnlyForEventRules = from.OnlyForEventRules;
        return to;
    }
}
