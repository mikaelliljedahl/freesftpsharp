using SshServer.Interfaces.EventRules;

namespace SshServer.EventRules;

/// <summary>A rule as the admin UI (and later the REST API, #67) gives it to <see cref="EventRuleAdministrationService"/>.</summary>
public sealed record EventRuleInput
{
    /// <summary>Null: a new rule.</summary>
    public int? Id { get; init; }

    public string Name { get; init; } = string.Empty;

    public string? Description { get; init; }

    public bool Enabled { get; init; } = true;

    public EventRuleTrigger Trigger { get; init; }

    public IReadOnlyList<string> EventTypes { get; init; } = [];

    public string? CronExpression { get; init; }

    public string? TimeZone { get; init; }

    public EventRuleConditions Conditions { get; init; } = new();

    public IReadOnlyList<EventRuleAction> Actions { get; init; } = [];
}
