using Microsoft.Extensions.Options;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;

namespace SshServer.EventRules;

/// <summary>The result of <see cref="EventRuleAdministrationService.SaveAsync"/>.</summary>
public sealed record EventRuleSaveResult(bool Succeeded, int? Id, IReadOnlyList<string> Errors)
{
    public static EventRuleSaveResult Failed(params string[] errors) => new(false, null, errors);
}

/// <summary>A rule for the provider events: the options of the actions are left out, they can have credentials in a URL or header.</summary>
public sealed record EventRuleSnapshot(string Name, bool Enabled, string Trigger, IReadOnlyList<string> EventTypes, string? CronExpression,
    string? TimeZone, IReadOnlyList<string> ActionTypes)
{
    public static EventRuleSnapshot From(EventRule r) => new(r.Name, r.Enabled, r.Trigger.ToString(), [.. r.EventTypes], r.CronExpression,
        r.TimeZone, r.Actions.Select(a => a.Type).ToArray());
}

/// <summary>
/// The one application service for event rules: the admin UI (and later the REST API, #67) uses it. It checks the rules,
/// saves, reloads the catalog, publishes the provider events, runs a rule now and reads the execution history. Every
/// call needs <see cref="AdminPermissions.ManageEvents"/> of the <see cref="AdminActor"/>.
/// </summary>
public sealed class EventRuleAdministrationService
{
    public const int RunsPageSize = 100;

    private readonly IEventRuleStore _store;
    private readonly EventRuleCatalog _catalog;
    private readonly EventRuleRunner _runner;
    private readonly IReadOnlyDictionary<string, IEventRuleAction> _actions;
    private readonly EventRuleOptions _options;
    private readonly TimeProvider _time;
    private readonly IEventBus? _events;

    public EventRuleAdministrationService(IEventRuleStore store, EventRuleCatalog catalog, EventRuleRunner runner, IEnumerable<IEventRuleAction> actions,
        IOptions<EventRuleOptions> options, TimeProvider time, IEventBus? events = null)
    {
        _store = store;
        _catalog = catalog;
        _runner = runner;
        _actions = EventRuleActions.ByType(actions);
        _options = options.Value;
        _time = time;
        _events = events;
    }

    /// <summary>False with the obsolete LiteDB settings provider: it has no event rules.</summary>
    public bool IsEnabled => _store.IsEnabled;

    /// <summary>The installed action types, by display name.</summary>
    public IReadOnlyList<IEventRuleAction> ActionTypes => _actions.Values.OrderBy(a => a.DisplayName, StringComparer.OrdinalIgnoreCase).ToArray();

    public IEventRuleAction? FindAction(string type) => _actions.GetValueOrDefault(type);

    /// <summary>True when the operator configured a mail server (<c>EventRules:Smtp:Host</c>).</summary>
    public bool IsEmailConfigured => _options.Smtp.IsConfigured;

    /// <summary>True when the operator allows the Command action (<c>EventRules:AllowCommands</c>).</summary>
    public bool AllowCommands => _options.AllowCommands;

    public Task<IReadOnlyList<EventRule>> ListAsync(AdminActor actor, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageEvents);
        return _store.ListAsync(ct);
    }

    public Task<EventRule?> GetAsync(AdminActor actor, int id, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageEvents);
        return _store.GetAsync(id, ct);
    }

    public async Task<EventRuleSaveResult> SaveAsync(AdminActor actor, EventRuleInput input, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageEvents);
        if (!_store.IsEnabled)
            return EventRuleSaveResult.Failed("Event rules need the SQLite settings database.");
        var errors = EventRuleValidator.Validate(input, _actions);
        if (errors.Count > 0)
            return new EventRuleSaveResult(false, null, errors);

        EventRule? before = null;
        EventRule rule;
        if (input.Id is { } id)
        {
            before = await _store.GetAsync(id, ct);
            if (before == null)
                return EventRuleSaveResult.Failed("The rule does not exist any more.");
            rule = await _store.GetAsync(id, ct) ?? before;
        }
        else
        {
            rule = new EventRule();
        }

        var trigger = input.Trigger;
        rule.Name = input.Name.Trim();
        rule.Description = string.IsNullOrWhiteSpace(input.Description) ? null : input.Description.Trim();
        rule.Enabled = input.Enabled;
        rule.Trigger = trigger;
        rule.EventTypes = trigger == EventRuleTrigger.Event ? input.EventTypes.Select(EventNames.Canonical).Distinct().ToList() : [];
        rule.CronExpression = trigger == EventRuleTrigger.Schedule ? input.CronExpression?.Trim() : null;
        rule.TimeZone = trigger == EventRuleTrigger.Schedule && !string.IsNullOrWhiteSpace(input.TimeZone) ? input.TimeZone.Trim() : null;
        rule.Conditions = Clean(input.Conditions);
        rule.Actions = input.Actions.Select(a => new EventRuleAction
        {
            Type = _actions[a.Type].Type,
            Options = a.Options.Where(o => !string.IsNullOrEmpty(o.Value)).ToDictionary(o => o.Key, o => o.Value),
            StopOnFailure = a.StopOnFailure && !a.IsFailureAction,
            IsFailureAction = a.IsFailureAction,
        }).ToList();

        var saved = before == null ? await _store.AddAsync(rule, ct) : await _store.UpdateAsync(rule, ct);
        if (!saved)
            return EventRuleSaveResult.Failed($"A rule with the name {rule.Name} already exists.");

        await _catalog.ReloadAsync(ct);
        await PublishAsync(actor, before == null ? ProviderAction.Add : ProviderAction.Update, rule, ChangedFields(before, rule), ct);
        return new EventRuleSaveResult(true, rule.Id, []);
    }

    public async Task<bool> RemoveAsync(AdminActor actor, int id, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageEvents);
        var rule = await _store.GetAsync(id, ct);
        if (rule == null || !await _store.RemoveAsync(id, ct))
            return false;
        await _catalog.ReloadAsync(ct);
        await PublishAsync(actor, ProviderAction.Delete, rule, [], ct);
        return true;
    }

    /// <summary>
    /// Runs a scheduled or on-demand rule now (also a disabled one) and waits for it: one run, or one per user for the
    /// actions on files. Null: no such rule, or a rule on events (it needs an event).
    /// </summary>
    public async Task<IReadOnlyList<EventRuleRun>?> RunNowAsync(AdminActor actor, int id, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageEvents);
        var rule = await _store.GetAsync(id, ct);
        if (rule == null || rule.Trigger == EventRuleTrigger.Event)
            return null;
        return await _runner.RunWithoutEventAsync(new ActiveEventRule(rule), EventRuleRunner.OnDemandTrigger, ct);
    }

    public Task<IReadOnlyList<EventRuleRun>> ListRunsAsync(AdminActor actor, int ruleId, CancellationToken ct)
    {
        actor.Demand(AdminPermissions.ManageEvents);
        return _store.ListRunsAsync(ruleId, RunsPageSize, ct);
    }

    private static EventRuleConditions Clean(EventRuleConditions c) => new()
    {
        Users = c.Users.Select(u => u.Trim()).Where(u => u.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
        Protocols = c.Protocols.Select(p => p.Trim()).Where(p => p.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
        PathGlob = string.IsNullOrWhiteSpace(c.PathGlob) ? null : c.PathGlob.Trim(),
        MinFileSize = c.MinFileSize,
        MaxFileSize = c.MaxFileSize,
        Statuses = c.Statuses.Select(s => Enum.Parse<FileEventStatus>(s, ignoreCase: true).ToString()).Distinct().ToList(),
        ObjectTypes = c.ObjectTypes.Select(s => Enum.Parse<ProviderObjectType>(s, ignoreCase: true).ToString()).Distinct().ToList(),
    };

    private static IReadOnlyList<string> ChangedFields(EventRule? before, EventRule after)
    {
        if (before == null)
            return [];
        var changed = new List<string>();
        void Check(string name, bool same)
        {
            if (!same)
                changed.Add(name);
        }
        Check(nameof(EventRule.Name), before.Name == after.Name);
        Check(nameof(EventRule.Description), before.Description == after.Description);
        Check(nameof(EventRule.Enabled), before.Enabled == after.Enabled);
        Check(nameof(EventRule.Trigger), before.Trigger == after.Trigger);
        Check(nameof(EventRule.EventTypes), before.EventTypes.SequenceEqual(after.EventTypes));
        Check(nameof(EventRule.CronExpression), before.CronExpression == after.CronExpression);
        Check(nameof(EventRule.TimeZone), before.TimeZone == after.TimeZone);
        Check(nameof(EventRule.Conditions), System.Text.Json.JsonSerializer.Serialize(before.Conditions) == System.Text.Json.JsonSerializer.Serialize(after.Conditions));
        Check(nameof(EventRule.Actions), System.Text.Json.JsonSerializer.Serialize(before.Actions) == System.Text.Json.JsonSerializer.Serialize(after.Actions));
        return changed;
    }

    private async Task PublishAsync(AdminActor actor, ProviderAction action, EventRule rule, IReadOnlyList<string> changed, CancellationToken ct)
    {
        if (_events == null)
            return;
        await _events.PublishAsync(new ProviderEvent(action, ProviderObjectType.EventRule, rule.Name)
        {
            Timestamp = _time.GetUtcNow(),
            Actor = actor.AuditName,
            Object = EventRuleSnapshot.From(rule),
            ChangedFields = changed,
        }, ct);
    }
}
