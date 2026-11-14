using Cronos;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;

namespace SshServer.EventRules;

/// <summary>The rules of an event rule. Returns the errors as texts for the admin UI; an empty list: valid.</summary>
public static class EventRuleValidator
{
    public const int MaxActions = 20;

    public static IReadOnlyList<string> Validate(EventRuleInput input, IReadOnlyDictionary<string, IEventRuleAction> actions)
    {
        var errors = new List<string>();
        var name = input.Name?.Trim() ?? string.Empty;
        if (name.Length == 0)
            errors.Add("Enter a name.");
        else if (name.Length > EventRule.MaxNameLength)
            errors.Add($"The name can have at most {EventRule.MaxNameLength} characters.");
        if (input.Description is { Length: > 1000 })
            errors.Add("The description can have at most 1000 characters.");

        switch (input.Trigger)
        {
            case EventRuleTrigger.Event:
                if (input.EventTypes.Count == 0)
                    errors.Add("Select one or more events.");
                var unknown = input.EventTypes.Where(e => !EventNames.IsKnown(e)).ToArray();
                if (unknown.Length > 0)
                    errors.Add("Unknown events: " + string.Join(", ", unknown) + ".");
                var pre = input.EventTypes.Count(EventNames.PreEvents.Contains);
                if (pre > 0 && pre < input.EventTypes.Count)
                    errors.Add("A rule on Pre* events runs before the operation; it cannot have other events too. Make two rules.");
                break;
            case EventRuleTrigger.Schedule:
                try
                {
                    EventRuleSchedule.ParseCron(input.CronExpression);
                }
                catch (CronFormatException ex)
                {
                    errors.Add("The schedule is not valid: " + ex.Message);
                }
                try
                {
                    EventRuleSchedule.ParseTimeZone(input.TimeZone);
                }
                catch (Exception ex) when (ex is TimeZoneNotFoundException or InvalidTimeZoneException)
                {
                    errors.Add($"The time zone {input.TimeZone} is not known on this server. Use an IANA id such as Europe/Stockholm, or leave it empty for UTC.");
                }
                break;
            case EventRuleTrigger.OnDemand:
                break;
            default:
                errors.Add("Select a trigger.");
                break;
        }

        ValidateConditions(input.Conditions, errors);

        if (input.Actions.Count == 0)
            errors.Add("Add one or more actions.");
        else if (input.Actions.Count > MaxActions)
            errors.Add($"A rule can have at most {MaxActions} actions.");
        else if (input.Actions.All(a => a.IsFailureAction))
            errors.Add("A rule needs an action that is not a failure action.");

        var step = 0;
        foreach (var action in input.Actions)
        {
            step++;
            if (!actions.TryGetValue(action.Type ?? string.Empty, out var plugin))
            {
                errors.Add($"Action {step}: the type {action.Type} is not installed on this server.");
                continue;
            }
            foreach (var error in plugin.Validate(action.Options))
                errors.Add($"Action {step} ({plugin.DisplayName}): {error}");
            foreach (var field in plugin.Fields.Where(f => f.Placeholders))
            {
                if (action.Options.TryGetValue(field.Key, out var value))
                    foreach (var error in EventTemplate.Validate(value))
                        errors.Add($"Action {step} ({plugin.DisplayName}), {field.Label}: {error}");
            }
        }
        return errors;
    }

    private static void ValidateConditions(EventRuleConditions conditions, List<string> errors)
    {
        if (conditions.Users.Any(string.IsNullOrWhiteSpace))
            errors.Add("A user name in the conditions is empty.");
        if (conditions.Protocols.Any(string.IsNullOrWhiteSpace))
            errors.Add("A protocol in the conditions is empty.");
        if (!string.IsNullOrWhiteSpace(conditions.PathGlob) && !conditions.PathGlob.Trim().StartsWith('/'))
            errors.Add("The path condition is a virtual path and starts with '/', for example /incoming/*.");
        if (conditions.MinFileSize < 0 || conditions.MaxFileSize < 0)
            errors.Add("A file size cannot be negative.");
        if (conditions.MinFileSize is { } min && conditions.MaxFileSize is { } max && min > max)
            errors.Add("The smallest file size is larger than the largest.");
        var statuses = conditions.Statuses.Where(s => !Enum.TryParse<FileEventStatus>(s, ignoreCase: true, out _)).ToArray();
        if (statuses.Length > 0)
            errors.Add("Unknown file results: " + string.Join(", ", statuses) + ".");
        var types = conditions.ObjectTypes.Where(s => !Enum.TryParse<ProviderObjectType>(s, ignoreCase: true, out _)).ToArray();
        if (types.Length > 0)
            errors.Add("Unknown object types: " + string.Join(", ", types) + ".");
    }
}
