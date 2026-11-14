namespace SshServer.Interfaces.EventRules;

/// <summary>
/// The event rules (#68) and their execution history in the settings store. The event rules plug-in and the admin UI
/// use it through this interface. The returned objects are detached copies.
/// </summary>
public interface IEventRuleStore
{
    /// <summary>False when the settings store has no event rule tables (the obsolete LiteDB provider): there are no rules.</summary>
    bool IsEnabled { get; }

    Task<IReadOnlyList<EventRule>> ListAsync(CancellationToken ct);

    Task<EventRule?> GetAsync(int id, CancellationToken ct);

    /// <summary>Adds the rule and sets its <see cref="EventRule.Id"/>. False when the name is already used.</summary>
    Task<bool> AddAsync(EventRule rule, CancellationToken ct);

    /// <summary>
    /// Saves the fields of the rule, but not <see cref="EventRule.LastScheduledRunUtc"/>. False when there is no such
    /// rule or the new name is already used.
    /// </summary>
    Task<bool> UpdateAsync(EventRule rule, CancellationToken ct);

    /// <summary>Removes the rule and its runs. False when there is no such rule.</summary>
    Task<bool> RemoveAsync(int id, CancellationToken ct);

    /// <summary>
    /// Takes the occurrence <paramref name="occurrenceUtc"/> of the schedule of a rule for this node: true when no node
    /// took it (or a later one) before. One conditional update, so with several nodes on one database exactly one
    /// node gets true.
    /// </summary>
    Task<bool> TryClaimScheduledRunAsync(int ruleId, DateTime occurrenceUtc, CancellationToken ct);

    /// <summary>Adds a run and removes the oldest runs of the rule beyond <paramref name="keep"/>.</summary>
    Task AddRunAsync(EventRuleRun run, int keep, CancellationToken ct);

    /// <summary>The newest runs of a rule.</summary>
    Task<IReadOnlyList<EventRuleRun>> ListRunsAsync(int ruleId, int take, CancellationToken ct);
}
