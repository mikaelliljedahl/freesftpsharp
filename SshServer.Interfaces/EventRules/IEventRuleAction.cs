using SshServer.Interfaces.Events;

namespace SshServer.Interfaces.EventRules;

/// <summary>
/// An action type of the event rules (#68), for example "Email", "Move" or "Webhook": a plug-in. Register it as a
/// singleton <c>IEventRuleAction</c>; the rules engine finds it by <see cref="Type"/> and never knows the class. The admin
/// UI shows the <see cref="Fields"/>, and the options of a rule step (<see cref="EventRuleAction.Options"/>) are the values
/// of these fields.
/// </summary>
public interface IEventRuleAction
{
    /// <summary>The unique name of the type, stored in <see cref="EventRuleAction.Type"/>.</summary>
    string Type { get; }

    /// <summary>The name for the admin UI.</summary>
    string DisplayName { get; }

    /// <summary>One sentence for the admin UI.</summary>
    string Description { get; }

    /// <summary>
    /// True: the action works on the files of a user (<see cref="EventActionContext.User"/> is set). A scheduled or
    /// on-demand rule with such an action runs once per matching user.
    /// </summary>
    bool NeedsUser { get; }

    /// <summary>The options of the action, in the order of the admin UI.</summary>
    IReadOnlyList<EventActionField> Fields { get; }

    /// <summary>The errors of the options, for the admin; empty when they are valid.</summary>
    IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> options);

    /// <summary>
    /// Runs the action. A failure is a <see cref="EventActionResult.Failed"/> result or an exception; the message is
    /// for the execution history, so it never contains a secret.
    /// </summary>
    Task<EventActionResult> ExecuteAsync(EventActionContext context, CancellationToken ct);
}

/// <summary>The kind of input of an <see cref="EventActionField"/>.</summary>
public enum EventActionFieldKind
{
    Text,

    /// <summary>Several lines, for example one path per line.</summary>
    MultilineText,

    Number,

    Boolean,

    /// <summary>One of <see cref="EventActionField.Choices"/>.</summary>
    Choice,
}

/// <summary>One option of an <see cref="IEventRuleAction"/>.</summary>
/// <param name="Key">The key in <see cref="EventRuleAction.Options"/>.</param>
/// <param name="Label">The label of the admin UI.</param>
/// <param name="Kind">The input.</param>
public sealed record EventActionField(string Key, string Label, EventActionFieldKind Kind)
{
    /// <summary>A hint under the input.</summary>
    public string? Help { get; init; }

    /// <summary>The value of a new action.</summary>
    public string? DefaultValue { get; init; }

    /// <summary>True: the value may have placeholders such as <c>{{VirtualPath}}</c>.</summary>
    public bool Placeholders { get; init; }

    /// <summary>The values of a <see cref="EventActionFieldKind.Choice"/>.</summary>
    public IReadOnlyList<string> Choices { get; init; } = [];
}

/// <summary>Everything an action needs for one run.</summary>
public sealed class EventActionContext
{
    private readonly Func<string, string> _render;

    /// <param name="render">Replaces the placeholders of a template with the values of this run.</param>
    public EventActionContext(EventRule rule, IEvent? @event, User? user, IReadOnlyDictionary<string, string> options,
        IDictionary<string, string> values, DateTimeOffset now, Func<string, string> render)
    {
        Rule = rule;
        Event = @event;
        User = user;
        Options = options;
        Values = values;
        Now = now;
        _render = render;
    }

    public EventRule Rule { get; }

    /// <summary>The event of the trigger; null for a scheduled or on-demand run.</summary>
    public IEvent? Event { get; }

    /// <summary>The user of the run: the user of the event, or the user of a scheduled run; null when there is none.</summary>
    public User? User { get; }

    /// <summary>The options of this step, not rendered.</summary>
    public IReadOnlyDictionary<string, string> Options { get; }

    /// <summary>
    /// Values that an action gives to the next actions of the same run, for example "RetentionDeleted". They are
    /// placeholders too (<c>{{RetentionDeleted}}</c>).
    /// </summary>
    public IDictionary<string, string> Values { get; }

    /// <summary>The start of the run.</summary>
    public DateTimeOffset Now { get; }

    /// <summary>Replaces the placeholders of <paramref name="template"/>.</summary>
    public string Render(string template) => _render(template);

    /// <summary>The option, not rendered; <paramref name="fallback"/> when it is missing or empty.</summary>
    public string Option(string key, string fallback = "")
        => Options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : fallback;

    /// <summary>The option with its placeholders replaced.</summary>
    public string RenderOption(string key, string fallback = "") => Render(Option(key, fallback));

    public bool BoolOption(string key) => bool.TryParse(Option(key), out var value) && value;
}

/// <summary>How an action ended.</summary>
public enum EventActionOutcome
{
    Ok,
    Failed,

    /// <summary>The action did not run, for example because the email server is not configured. It is not a failure.</summary>
    Skipped,
}

/// <summary>The result of <see cref="IEventRuleAction.ExecuteAsync"/>.</summary>
public sealed record EventActionResult(EventActionOutcome Outcome, string Message)
{
    public static EventActionResult Ok(string message) => new(EventActionOutcome.Ok, message);

    public static EventActionResult Failed(string message) => new(EventActionOutcome.Failed, message);

    public static EventActionResult Skipped(string message) => new(EventActionOutcome.Skipped, message);

    public bool IsFailure => Outcome == EventActionOutcome.Failed;
}
