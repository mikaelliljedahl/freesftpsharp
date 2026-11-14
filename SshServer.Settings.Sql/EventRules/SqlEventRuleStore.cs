using Microsoft.EntityFrameworkCore;
using SshServer.Interfaces.EventRules;

namespace SshServer.Settings.Sql.EventRules;

/// <summary>
/// <see cref="IEventRuleStore"/> in the tables EventRules and EventRuleRuns of the settings database. The settings
/// repository creates and migrates the database at the start; this class only reads and writes rows, each call with its
/// own context. The claim of a schedule occurrence is one conditional UPDATE, so several nodes (#75) run it once.
/// </summary>
public sealed class SqlEventRuleStore : IEventRuleStore
{
    private readonly DbContextOptions<SettingsDbContext> _options;

    public SqlEventRuleStore(DbContextOptions<SettingsDbContext> options)
    {
        _options = options;
    }

    public bool IsEnabled => true;

    private SettingsDbContext CreateContext() => new(_options);

    public async Task<IReadOnlyList<EventRule>> ListAsync(CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.EventRules.AsNoTracking().OrderBy(r => r.Name).ToListAsync(ct);
    }

    public async Task<EventRule?> GetAsync(int id, CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.EventRules.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id, ct);
    }

    public async Task<bool> AddAsync(EventRule rule, CancellationToken ct)
    {
        await using var db = CreateContext();
        if (await NameIsUsedAsync(db, rule.Name, exceptId: null, ct))
            return false;
        var row = Copy(rule, new EventRule());
        db.EventRules.Add(row);
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            return false; // the unique name, added at the same time
        }
        rule.Id = row.Id;
        return true;
    }

    public async Task<bool> UpdateAsync(EventRule rule, CancellationToken ct)
    {
        await using var db = CreateContext();
        var row = await db.EventRules.FirstOrDefaultAsync(r => r.Id == rule.Id, ct);
        if (row == null || await NameIsUsedAsync(db, rule.Name, exceptId: rule.Id, ct))
            return false;
        Copy(rule, row);
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
        // The runs first: the foreign key cascades too, but SQLite needs foreign keys on for it.
        await db.EventRuleRuns.Where(r => r.RuleId == id).ExecuteDeleteAsync(ct);
        return await db.EventRules.Where(r => r.Id == id).ExecuteDeleteAsync(ct) > 0;
    }

    public async Task<bool> TryClaimScheduledRunAsync(int ruleId, DateTime occurrenceUtc, CancellationToken ct)
    {
        await using var db = CreateContext();
        var updated = await db.EventRules
            .Where(r => r.Id == ruleId && (r.LastScheduledRunUtc == null || r.LastScheduledRunUtc < occurrenceUtc))
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.LastScheduledRunUtc, occurrenceUtc), ct);
        return updated == 1;
    }

    public async Task AddRunAsync(EventRuleRun run, int keep, CancellationToken ct)
    {
        await using var db = CreateContext();
        run.Id = 0;
        if (run.Message.Length > EventRuleRun.MaxMessageLength)
            run.Message = run.Message[..(EventRuleRun.MaxMessageLength - 1)] + "…";
        db.EventRuleRuns.Add(run);
        await db.SaveChangesAsync(ct);

        // The oldest runs beyond the limit: the id of the newest one that goes.
        var oldestKept = await db.EventRuleRuns.Where(r => r.RuleId == run.RuleId)
            .OrderByDescending(r => r.Id).Skip(Math.Max(keep, 1) - 1).Select(r => (long?)r.Id).FirstOrDefaultAsync(ct);
        if (oldestKept is { } id)
            await db.EventRuleRuns.Where(r => r.RuleId == run.RuleId && r.Id < id).ExecuteDeleteAsync(ct);
    }

    public async Task<IReadOnlyList<EventRuleRun>> ListRunsAsync(int ruleId, int take, CancellationToken ct)
    {
        await using var db = CreateContext();
        return await db.EventRuleRuns.AsNoTracking()
            .Where(r => r.RuleId == ruleId)
            .OrderByDescending(r => r.Id)
            .Take(Math.Clamp(take, 0, 1000))
            .ToListAsync(ct);
    }

    private static async Task<bool> NameIsUsedAsync(SettingsDbContext db, string name, int? exceptId, CancellationToken ct)
    {
        var lower = name.Trim().ToLowerInvariant();
        return await db.EventRules.AnyAsync(r => r.Name.ToLower() == lower && (exceptId == null || r.Id != exceptId), ct);
    }

    /// <summary>All fields except the id and <see cref="EventRule.LastScheduledRunUtc"/> (the scheduler owns it).</summary>
    private static EventRule Copy(EventRule from, EventRule to)
    {
        to.Name = from.Name;
        to.Description = from.Description;
        to.Enabled = from.Enabled;
        to.Trigger = from.Trigger;
        to.EventTypes = [.. from.EventTypes];
        to.CronExpression = from.CronExpression;
        to.TimeZone = from.TimeZone;
        to.Conditions = new EventRuleConditions
        {
            Users = [.. from.Conditions.Users],
            Protocols = [.. from.Conditions.Protocols],
            PathGlob = from.Conditions.PathGlob,
            MinFileSize = from.Conditions.MinFileSize,
            MaxFileSize = from.Conditions.MaxFileSize,
            Statuses = [.. from.Conditions.Statuses],
            ObjectTypes = [.. from.Conditions.ObjectTypes],
        };
        to.Actions = from.Actions.Select(a => new EventRuleAction
        {
            Type = a.Type,
            Options = new Dictionary<string, string>(a.Options),
            StopOnFailure = a.StopOnFailure,
            IsFailureAction = a.IsFailureAction,
        }).ToList();
        return to;
    }
}
