using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using SshServer.EventRules;
using SshServer.Interfaces.EventRules;

namespace FxSshSftpServer.Models
{
    /// <summary>The add/edit form of an event rule. The rules are checked by <see cref="EventRuleAdministrationService"/>.</summary>
    public sealed class EventRuleForm
    {
        public const string DefaultCron = "0 3 * * *";

        public int? Id { get; set; }

        public bool IsNew => Id is null;

        public string Name { get; set; } = "";

        public string Description { get; set; } = "";

        public bool Enabled { get; set; } = true;

        public EventRuleTrigger Trigger { get; set; } = EventRuleTrigger.Event;

        public HashSet<string> EventTypes { get; } = new(StringComparer.OrdinalIgnoreCase);

        public string CronExpression { get; set; } = DefaultCron;

        public string TimeZone { get; set; } = "";

        /// <summary>The user patterns, one per line or separated by commas.</summary>
        public string Users { get; set; } = "";

        /// <summary>The protocols, separated by commas.</summary>
        public string Protocols { get; set; } = "";

        public string PathGlob { get; set; } = "";

        public long? MinFileSize { get; set; }

        public long? MaxFileSize { get; set; }

        public HashSet<string> Statuses { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>The object types of provider events, separated by commas.</summary>
        public string ObjectTypes { get; set; } = "";

        public List<EventRuleActionForm> Actions { get; } = new();

        public static EventRuleForm New() => new();

        public static EventRuleForm From(EventRule rule)
        {
            var form = new EventRuleForm
            {
                Id = rule.Id,
                Name = rule.Name,
                Description = rule.Description ?? "",
                Enabled = rule.Enabled,
                Trigger = rule.Trigger,
                CronExpression = rule.CronExpression ?? DefaultCron,
                TimeZone = rule.TimeZone ?? "",
                Users = string.Join(Environment.NewLine, rule.Conditions.Users),
                Protocols = string.Join(", ", rule.Conditions.Protocols),
                PathGlob = rule.Conditions.PathGlob ?? "",
                MinFileSize = rule.Conditions.MinFileSize,
                MaxFileSize = rule.Conditions.MaxFileSize,
                ObjectTypes = string.Join(", ", rule.Conditions.ObjectTypes),
            };
            form.EventTypes.UnionWith(rule.EventTypes);
            form.Statuses.UnionWith(rule.Conditions.Statuses);
            form.Actions.AddRange(rule.Actions.Select(a => new EventRuleActionForm
            {
                Type = a.Type,
                Options = new Dictionary<string, string>(a.Options, StringComparer.Ordinal),
                StopOnFailure = a.StopOnFailure,
                IsFailureAction = a.IsFailureAction,
            }));
            return form;
        }

        public EventRuleInput ToInput() => new()
        {
            Id = Id,
            Name = Name ?? "",
            Description = Description,
            Enabled = Enabled,
            Trigger = Trigger,
            EventTypes = EventTypes.ToList(),
            CronExpression = CronExpression,
            TimeZone = TimeZone,
            Conditions = new EventRuleConditions
            {
                Users = Split(Users),
                Protocols = Split(Protocols),
                PathGlob = PathGlob,
                MinFileSize = MinFileSize,
                MaxFileSize = MaxFileSize,
                Statuses = Statuses.ToList(),
                ObjectTypes = Split(ObjectTypes),
            },
            Actions = Actions.Select(a => new EventRuleAction
            {
                Type = a.Type,
                Options = new Dictionary<string, string>(a.Options),
                StopOnFailure = a.StopOnFailure,
                IsFailureAction = a.IsFailureAction,
            }).ToList(),
        };

        /// <summary>A short text of the trigger, for the list.</summary>
        public static string DescribeTrigger(EventRule rule) => rule.Trigger switch
        {
            EventRuleTrigger.Event => string.Join(", ", rule.EventTypes),
            EventRuleTrigger.Schedule => $"{rule.CronExpression} ({rule.TimeZone ?? "UTC"})",
            _ => "on demand",
        };

        private static List<string> Split(string text)
            => (text ?? "").Split([',', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    }

    /// <summary>One action of the form: its type and the values of the fields of the action plug-in.</summary>
    public sealed class EventRuleActionForm
    {
        public string Type { get; set; } = "";

        public Dictionary<string, string> Options { get; set; } = new(StringComparer.Ordinal);

        public bool StopOnFailure { get; set; }

        public bool IsFailureAction { get; set; }

        /// <summary>A new action with the default values of its fields.</summary>
        public static EventRuleActionForm New(IEventRuleAction action) => new()
        {
            Type = action.Type,
            Options = action.Fields
                .Where(f => f.DefaultValue != null || f.Kind == EventActionFieldKind.Choice && f.Choices.Count > 0)
                .ToDictionary(f => f.Key, f => f.DefaultValue ?? f.Choices[0], StringComparer.Ordinal),
        };

        public string Value(string key) => Options.TryGetValue(key, out var value) ? value : "";

        public bool Flag(string key) => bool.TryParse(Value(key), out var value) && value;

        public void Set(string key, object value)
            => Options[key] = value switch
            {
                bool b => b.ToString(CultureInfo.InvariantCulture),
                null => "",
                _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? "",
            };
    }
}
