namespace SshServer.Interfaces.EventRules;

/// <summary>What starts an <see cref="EventRule"/>.</summary>
public enum EventRuleTrigger
{
    /// <summary>One of the events in <see cref="EventRule.EventTypes"/>.</summary>
    Event,

    /// <summary>The cron expression <see cref="EventRule.CronExpression"/>.</summary>
    Schedule,

    /// <summary>Only the "Run now" button of the admin UI.</summary>
    OnDemand,
}

/// <summary>
/// An automation of the administrator (#68): when the trigger fires and the conditions match, the actions run in order,
/// for example "on an upload to <c>/incoming/*</c>: move the file to <c>/processed</c>, then send an email". The event
/// rules plug-in (<c>SshServer.EventRules</c>, <c>AddEventRules()</c>) runs them; the settings store keeps them through
/// <see cref="IEventRuleStore"/>. The rules of the fields are in the plug-in (<c>EventRuleValidator</c>).
/// </summary>
public sealed class EventRule
{
    public const int MaxNameLength = 100;

    public int Id { get; set; }

    /// <summary>A unique name (case-insensitive).</summary>
    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    public EventRuleTrigger Trigger { get; set; }

    /// <summary>
    /// For <see cref="EventRuleTrigger.Event"/>: the events, as "Category.Type" (for example "File.Upload",
    /// "Auth.IpBanned"). A rule on a <c>Pre*</c> event runs before the operation, and a failed action refuses it.
    /// </summary>
    public List<string> EventTypes { get; set; } = new();

    /// <summary>For <see cref="EventRuleTrigger.Schedule"/>: a cron expression with five fields, for example <c>0 3 * * *</c>.</summary>
    public string? CronExpression { get; set; }

    /// <summary>The time zone of <see cref="CronExpression"/> (IANA or Windows id); null: UTC.</summary>
    public string? TimeZone { get; set; }

    public EventRuleConditions Conditions { get; set; } = new();

    /// <summary>The actions, in the order they run.</summary>
    public List<EventRuleAction> Actions { get; set; } = new();

    /// <summary>
    /// The last occurrence of the schedule that a node ran. A node takes an occurrence with one conditional update of
    /// this column (<see cref="IEventRuleStore.TryClaimScheduledRunAsync"/>), so on several nodes a schedule runs once.
    /// </summary>
    public DateTime? LastScheduledRunUtc { get; set; }
}

/// <summary>The filters of an <see cref="EventRule"/>. An empty filter matches everything.</summary>
public sealed class EventRuleConditions
{
    /// <summary>
    /// The user names (case-insensitive; <c>*</c> is any text, <c>?</c> one character). An event rule needs an event of
    /// one of these users; a scheduled or on-demand rule runs its user actions for each user that matches (empty: every user).
    /// </summary>
    public List<string> Users { get; set; } = new();

    /// <summary>The protocols of the client, for example "SFTP" (case-insensitive).</summary>
    public List<string> Protocols { get; set; } = new();

    /// <summary>A glob over the virtual path (or target path) of a file event, see <c>PathGlob</c>. Set: only file events.</summary>
    public string? PathGlob { get; set; }

    /// <summary>The smallest file size of a file event, in bytes.</summary>
    public long? MinFileSize { get; set; }

    /// <summary>The largest file size of a file event, in bytes.</summary>
    public long? MaxFileSize { get; set; }

    /// <summary>The results of a file event (<c>FileEventStatus</c> names). Empty: every result.</summary>
    public List<string> Statuses { get; set; } = new();

    /// <summary>The object types of a provider event (<c>ProviderObjectType</c> names). Empty: every type.</summary>
    public List<string> ObjectTypes { get; set; } = new();
}

/// <summary>One step of an <see cref="EventRule"/>: an action plug-in (<see cref="IEventRuleAction"/>) with its options.</summary>
public sealed class EventRuleAction
{
    /// <summary>The <see cref="IEventRuleAction.Type"/>, for example "Email".</summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>The options of the action plug-in, by <see cref="EventActionField.Key"/>. Text values can have placeholders.</summary>
    public Dictionary<string, string> Options { get; set; } = new();

    /// <summary>True: when this action fails, the next actions do not run (the failure actions still run).</summary>
    public bool StopOnFailure { get; set; }

    /// <summary>True: the action runs only when another action of the rule failed.</summary>
    public bool IsFailureAction { get; set; }
}

/// <summary>The result of one run of an <see cref="EventRule"/>.</summary>
public enum EventRuleRunStatus
{
    Ok,

    /// <summary>An action failed; <see cref="EventRuleRun.Message"/> tells which.</summary>
    Failed,
}

/// <summary>One run of an <see cref="EventRule"/>, for the execution history of the admin UI.</summary>
public sealed class EventRuleRun
{
    public const int MaxMessageLength = 4000;

    public long Id { get; set; }

    public int RuleId { get; set; }

    public DateTime StartedUtc { get; set; }

    public long DurationMs { get; set; }

    public EventRuleRunStatus Status { get; set; }

    /// <summary>What started the run: the event name ("File.Upload"), "Schedule" or "OnDemand".</summary>
    public string Trigger { get; set; } = string.Empty;

    /// <summary>The user of the run, when it has one.</summary>
    public string? Username { get; set; }

    /// <summary>One line per action with its result.</summary>
    public string Message { get; set; } = string.Empty;
}
