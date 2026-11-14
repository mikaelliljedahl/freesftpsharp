using SshServer.Interfaces.EventRules;

namespace SshServer.Settings.Sql.EventRules;

/// <summary>The event rule store of the obsolete LiteDB settings provider: it has no event rule tables, so there are no rules.</summary>
public sealed class DisabledEventRuleStore : IEventRuleStore
{
    public bool IsEnabled => false;

    public Task<IReadOnlyList<EventRule>> ListAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<EventRule>>([]);

    public Task<EventRule?> GetAsync(int id, CancellationToken ct) => Task.FromResult<EventRule?>(null);

    public Task<bool> AddAsync(EventRule rule, CancellationToken ct) => Task.FromResult(false);

    public Task<bool> UpdateAsync(EventRule rule, CancellationToken ct) => Task.FromResult(false);

    public Task<bool> RemoveAsync(int id, CancellationToken ct) => Task.FromResult(false);

    public Task<bool> TryClaimScheduledRunAsync(int ruleId, DateTime occurrenceUtc, CancellationToken ct) => Task.FromResult(false);

    public Task AddRunAsync(EventRuleRun run, int keep, CancellationToken ct) => Task.CompletedTask;

    public Task<IReadOnlyList<EventRuleRun>> ListRunsAsync(int ruleId, int take, CancellationToken ct)
        => Task.FromResult<IReadOnlyList<EventRuleRun>>([]);
}
