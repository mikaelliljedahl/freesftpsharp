using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Storage;

namespace SshServer.EventRules;

/// <summary>
/// The engine of one rule run: the actions in order, then the failure actions when one failed. It knows the actions only
/// through <see cref="IEventRuleAction"/> (found by <see cref="IEventRuleAction.Type"/>); a new action type is a new
/// plug-in, never a change here. Every run is stored in the execution history.
/// </summary>
public sealed class EventRuleRunner
{
    /// <summary>
    /// The protocol of the file operations of the actions (<see cref="ClientContext.Protocol"/>): their events are in the
    /// audit log, but they never start a rule, so a rule cannot trigger itself.
    /// </summary>
    public const string Protocol = "EventRules";

    public const string ScheduleTrigger = "Schedule";
    public const string OnDemandTrigger = "OnDemand";

    private readonly IReadOnlyDictionary<string, IEventRuleAction> _actions;
    private readonly IEventRuleStore _store;
    private readonly ISettingsRepository _users;
    private readonly EventRuleOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    public EventRuleRunner(IEnumerable<IEventRuleAction> actions, IEventRuleStore store, ISettingsRepository users, IOptions<EventRuleOptions> options,
        TimeProvider time, ILogger<EventRuleRunner> logger)
    {
        _actions = EventRuleActions.ByType(actions);
        _store = store;
        _users = users;
        _options = options.Value;
        _time = time;
        _logger = logger;
    }

    /// <summary>True when the event comes from an action of a rule (it never starts a rule).</summary>
    public static bool IsFromAnAction(IEvent @event) => @event is FileEvent { Protocol: Protocol };

    /// <summary>Runs the rule for an event, with the user of the event.</summary>
    public Task<EventRuleRun> RunForEventAsync(EventRule rule, IEvent @event, CancellationToken ct)
    {
        var username = @event switch
        {
            FileEvent file => file.Username,
            AuthEvent auth => auth.Username,
            _ => null,
        };
        var user = string.IsNullOrEmpty(username) ? null : _users.GetUser(username);
        return RunAsync(rule, @event, EventNames.Of(@event), user, ct);
    }

    /// <summary>
    /// A scheduled or on-demand run. With an action that needs a user, the actions run once for each user that passes the
    /// user condition; else once.
    /// </summary>
    public async Task<IReadOnlyList<EventRuleRun>> RunWithoutEventAsync(ActiveEventRule rule, string trigger, CancellationToken ct)
    {
        var needsUser = rule.Definition.Actions.Any(a => _actions.TryGetValue(a.Type, out var action) && action.NeedsUser);
        if (!needsUser)
            return [await RunAsync(rule.Definition, null, trigger, null, ct)];

        var runs = new List<EventRuleRun>();
        foreach (var user in _users.GetAllUsers().Where(u => rule.MatchesUser(u.Username)).OrderBy(u => u.Username, StringComparer.OrdinalIgnoreCase))
            runs.Add(await RunAsync(rule.Definition, null, trigger, user, ct));
        return runs;
    }

    private async Task<EventRuleRun> RunAsync(EventRule rule, IEvent? @event, string trigger, User? user, CancellationToken ct)
    {
        var started = _time.GetUtcNow();
        var stopwatch = Stopwatch.StartNew();
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var lines = new List<string>();
        var failed = false;
        var step = 0;

        foreach (var action in rule.Actions.Where(a => !a.IsFailureAction))
        {
            step++;
            var result = await ExecuteAsync(rule, action, @event, trigger, user, started, values, ct);
            lines.Add(Line(step, action, result));
            if (!result.IsFailure)
                continue;
            failed = true;
            if (action.StopOnFailure)
            {
                lines.Add("The next actions did not run (stop on failure).");
                break;
            }
        }

        if (failed)
        {
            foreach (var action in rule.Actions.Where(a => a.IsFailureAction))
            {
                step++;
                var result = await ExecuteAsync(rule, action, @event, trigger, user, started, values, ct);
                lines.Add(Line(step, action, result) + " (failure action)");
            }
        }

        var run = new EventRuleRun
        {
            RuleId = rule.Id,
            StartedUtc = started.UtcDateTime,
            DurationMs = stopwatch.ElapsedMilliseconds,
            Status = failed ? EventRuleRunStatus.Failed : EventRuleRunStatus.Ok,
            Trigger = trigger,
            Username = user?.Username,
            Message = lines.Count == 0 ? "The rule has no actions." : string.Join(Environment.NewLine, lines),
        };
        if (failed)
            _logger.LogWarning("The event rule {Rule} failed on {Trigger} for {User}: {Message}", rule.Name, trigger, user?.Username, run.Message);
        else
            _logger.LogInformation("The event rule {Rule} ran on {Trigger} for {User} in {Duration} ms.", rule.Name, trigger, user?.Username, run.DurationMs);

        try
        {
            await _store.AddRunAsync(run, _options.RunHistoryPerRule, CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "The run of the event rule {Rule} could not be stored in the execution history.", rule.Name);
        }
        return run;
    }

    private async Task<EventActionResult> ExecuteAsync(EventRule rule, EventRuleAction step, IEvent? @event, string trigger, User? user,
        DateTimeOffset now, Dictionary<string, string> values, CancellationToken ct)
    {
        if (!_actions.TryGetValue(step.Type, out var action))
            return EventActionResult.Failed($"The action type {step.Type} is not installed on this server.");
        if (action.NeedsUser && user == null)
            return EventActionResult.Failed("This action works on the files of a user, and the run has no user (or the user does not exist).");

        var context = new EventActionContext(rule, @event, user, step.Options, values, now,
            template => EventTemplate.Render(template, EventPlaceholders.For(rule, @event, trigger, user, now, values)));
        try
        {
            return await action.ExecuteAsync(context, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (FileSystemException ex)
        {
            return EventActionResult.Failed(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "The action {Action} of the event rule {Rule} failed.", step.Type, rule.Name);
            return EventActionResult.Failed(ex.Message);
        }
    }

    private static string Line(int step, EventRuleAction action, EventActionResult result)
        => $"{step}. {action.Type}: {result.Outcome}. {result.Message}".TrimEnd();
}

/// <summary>The action plug-ins by type.</summary>
public static class EventRuleActions
{
    /// <summary>The actions by <see cref="IEventRuleAction.Type"/> (case-insensitive); two plug-ins with one type are an error.</summary>
    public static IReadOnlyDictionary<string, IEventRuleAction> ByType(IEnumerable<IEventRuleAction> actions)
    {
        var byType = new Dictionary<string, IEventRuleAction>(StringComparer.OrdinalIgnoreCase);
        foreach (var action in actions)
        {
            if (!byType.TryAdd(action.Type, action))
                throw new InvalidOperationException($"Two event rule actions have the type {action.Type}.");
        }
        return byType;
    }
}
