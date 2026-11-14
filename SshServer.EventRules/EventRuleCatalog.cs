using Cronos;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Storage;

namespace SshServer.EventRules;

/// <summary>An enabled rule, ready to match: its filters and its schedule parsed.</summary>
public sealed class ActiveEventRule
{
    private readonly HashSet<string> _events;
    private readonly NamePattern[] _users;
    private readonly HashSet<string> _protocols;
    private readonly PathGlob? _glob;
    private readonly HashSet<string> _statuses;
    private readonly HashSet<string> _objectTypes;

    public ActiveEventRule(EventRule definition)
    {
        Definition = definition;
        var conditions = definition.Conditions;
        _events = new HashSet<string>(definition.EventTypes, StringComparer.OrdinalIgnoreCase);
        _users = conditions.Users.Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => new NamePattern(u.Trim())).ToArray();
        _protocols = new HashSet<string>(conditions.Protocols, StringComparer.OrdinalIgnoreCase);
        _glob = string.IsNullOrWhiteSpace(conditions.PathGlob) ? null : PathGlob.Parse(conditions.PathGlob.Trim());
        _statuses = new HashSet<string>(conditions.Statuses, StringComparer.OrdinalIgnoreCase);
        _objectTypes = new HashSet<string>(conditions.ObjectTypes, StringComparer.OrdinalIgnoreCase);
        IsPre = _events.Count > 0 && _events.All(EventNames.PreEvents.Contains);
        if (definition.Trigger == EventRuleTrigger.Schedule)
        {
            try
            {
                Cron = EventRuleSchedule.ParseCron(definition.CronExpression);
                TimeZone = EventRuleSchedule.ParseTimeZone(definition.TimeZone);
            }
            catch (Exception ex) when (ex is CronFormatException or TimeZoneNotFoundException or InvalidTimeZoneException or ArgumentException)
            {
                Error = ex.Message;
            }
        }
    }

    public EventRule Definition { get; }

    public int Id => Definition.Id;

    public string Name => Definition.Name;

    /// <summary>True for a rule on <c>Pre*</c> events: it runs before the operation and can refuse it.</summary>
    public bool IsPre { get; }

    /// <summary>The schedule of a scheduled rule; null when the expression is not valid (<see cref="Error"/>).</summary>
    public CronExpression? Cron { get; }

    public TimeZoneInfo TimeZone { get; } = TimeZoneInfo.Utc;

    /// <summary>Why the schedule cannot run (the expression or the time zone is not valid any more).</summary>
    public string? Error { get; }

    /// <summary>True when a user name passes the user condition (no condition: every user).</summary>
    public bool MatchesUser(string? username) => _users.Length == 0 || _users.Any(p => p.IsMatch(username));

    /// <summary>True when the event is a trigger of this rule and passes every condition.</summary>
    public bool Matches(IEvent @event, string eventName)
    {
        if (Definition.Trigger != EventRuleTrigger.Event || !_events.Contains(eventName))
            return false;

        var (user, protocol) = @event switch
        {
            FileEvent file => (file.Username, file.Protocol),
            AuthEvent auth => (auth.Username, auth.Protocol),
            _ => ((string?)null, (string?)null),
        };
        if (_users.Length > 0 && (user == null || !MatchesUser(user)))
            return false;
        if (_protocols.Count > 0 && (protocol == null || !_protocols.Contains(protocol)))
            return false;

        var conditions = Definition.Conditions;
        var fileConditions = _glob != null || conditions.MinFileSize != null || conditions.MaxFileSize != null || _statuses.Count > 0;
        if (fileConditions)
        {
            if (@event is not FileEvent file)
                return false;
            if (_glob != null && !_glob.IsMatch(file.VirtualPath) && (file.VirtualTargetPath == null || !_glob.IsMatch(file.VirtualTargetPath)))
                return false;
            if (conditions.MinFileSize is { } min && (file.FileSize == null || file.FileSize < min))
                return false;
            if (conditions.MaxFileSize is { } max && (file.FileSize == null || file.FileSize > max))
                return false;
            if (_statuses.Count > 0 && !_statuses.Contains(file.Status.ToString()))
                return false;
        }

        if (_objectTypes.Count > 0 && (@event is not ProviderEvent provider || !_objectTypes.Contains(provider.ObjectType.ToString())))
            return false;
        return true;
    }
}

/// <summary>The enabled rules at one time, by trigger.</summary>
public sealed class EventRuleCatalogSnapshot
{
    public static EventRuleCatalogSnapshot Empty { get; } = new([]);

    public EventRuleCatalogSnapshot(IReadOnlyList<ActiveEventRule> rules)
    {
        EventRules = rules.Where(r => r.Definition.Trigger == EventRuleTrigger.Event && !r.IsPre).ToArray();
        PreEventRules = rules.Where(r => r.Definition.Trigger == EventRuleTrigger.Event && r.IsPre).ToArray();
        ScheduledRules = rules.Where(r => r.Definition.Trigger == EventRuleTrigger.Schedule).ToArray();
    }

    /// <summary>The rules on events after the operation; they run in the background.</summary>
    public IReadOnlyList<ActiveEventRule> EventRules { get; }

    /// <summary>The rules on <c>Pre*</c> events; the operation waits for them.</summary>
    public IReadOnlyList<ActiveEventRule> PreEventRules { get; }

    public IReadOnlyList<ActiveEventRule> ScheduledRules { get; }
}

/// <summary>
/// The enabled rules in memory, so that an event costs no database read: with no rule, the sink and the hook return at
/// once. It is loaded at the first use, reloaded after each change in the admin UI and every 30 s by the scheduler (for
/// the changes of another node).
/// </summary>
public sealed class EventRuleCatalog
{
    public static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(30);

    private readonly IEventRuleStore _store;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _loadLock = new(1, 1);
    private volatile EventRuleCatalogSnapshot? _current;
    private long _loadedAt;

    public EventRuleCatalog(IEventRuleStore store, TimeProvider time, ILogger<EventRuleCatalog> logger)
    {
        _store = store;
        _time = time;
        _logger = logger;
    }

    /// <summary>The time since the last load; null before the first load.</summary>
    public TimeSpan? Age => _current == null ? null : _time.GetElapsedTime(Interlocked.Read(ref _loadedAt));

    /// <summary>The current rules; loads them at the first call.</summary>
    public ValueTask<EventRuleCatalogSnapshot> GetAsync(CancellationToken ct)
        => _current is { } current ? ValueTask.FromResult(current) : new ValueTask<EventRuleCatalogSnapshot>(LoadFirstAsync(ct));

    private async Task<EventRuleCatalogSnapshot> LoadFirstAsync(CancellationToken ct)
    {
        await _loadLock.WaitAsync(ct);
        try
        {
            return _current ?? await LoadAsync(ct);
        }
        finally
        {
            _loadLock.Release();
        }
    }

    /// <summary>Reads the rules from the store again.</summary>
    public async Task<EventRuleCatalogSnapshot> ReloadAsync(CancellationToken ct)
    {
        await _loadLock.WaitAsync(ct);
        try
        {
            return await LoadAsync(ct);
        }
        finally
        {
            _loadLock.Release();
        }
    }

    private async Task<EventRuleCatalogSnapshot> LoadAsync(CancellationToken ct)
    {
        EventRuleCatalogSnapshot snapshot;
        if (!_store.IsEnabled)
        {
            snapshot = EventRuleCatalogSnapshot.Empty;
        }
        else
        {
            var rules = (await _store.ListAsync(ct)).Where(r => r.Enabled).Select(r => new ActiveEventRule(r)).ToArray();
            foreach (var broken in rules.Where(r => r.Error != null))
                _logger.LogError("The schedule of the event rule {Rule} is not valid; it does not run: {Error}", broken.Name, broken.Error);
            snapshot = new EventRuleCatalogSnapshot(rules);
        }
        Interlocked.Exchange(ref _loadedAt, _time.GetTimestamp());
        _current = snapshot;
        return snapshot;
    }
}
