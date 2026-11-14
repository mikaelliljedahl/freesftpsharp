using SshServer.Interfaces.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Webhooks;
using SshServer.Interfaces.Cluster;

namespace SshServer.Webhooks;

/// <summary>An enabled webhook, ready to match events and to send: its filters parsed and its secret decrypted.</summary>
public sealed class ActiveWebhook
{
    private readonly HashSet<string> _eventTypes;
    private readonly HashSet<string> _users;
    private readonly PathGlob? _glob;

    public ActiveWebhook(Webhook definition, string? secret, string? error)
    {
        Definition = definition;
        Secret = secret;
        Error = error;
        _eventTypes = new HashSet<string>(definition.EventTypes, StringComparer.OrdinalIgnoreCase);
        _users = new HashSet<string>(definition.Users, StringComparer.OrdinalIgnoreCase);
        _glob = string.IsNullOrWhiteSpace(definition.PathGlob) ? null : PathGlob.Parse(definition.PathGlob.Trim());
    }

    public Webhook Definition { get; }

    public int Id => Definition.Id;

    public string Name => Definition.Name;

    /// <summary>The plain secret of the signature; null: no signature.</summary>
    public string? Secret { get; }

    /// <summary>Why the webhook cannot send now (the secret cannot be decrypted, the URL is not allowed); a request is then not sent.</summary>
    public string? Error { get; }

    /// <summary>True when the event passes the event type, user and path filters.</summary>
    public bool Matches(IEvent @event, string eventName)
    {
        if (_eventTypes.Count == 0 ? EventNames.PreEvents.Contains(eventName) : !_eventTypes.Contains(eventName))
            return false;

        if (_users.Count > 0)
        {
            var user = @event switch
            {
                FileEvent file => file.Username,
                AuthEvent auth => auth.Username,
                _ => null,
            };
            if (user == null || !_users.Contains(user))
                return false;
        }

        if (_glob != null)
        {
            if (@event is not FileEvent file)
                return false;
            if (!_glob.IsMatch(file.VirtualPath) && (file.VirtualTargetPath == null || !_glob.IsMatch(file.VirtualTargetPath)))
                return false;
        }
        return true;
    }
}

/// <summary>The enabled webhooks at one time: the asynchronous and the synchronous ones, and the ones only for event rules.</summary>
public sealed class WebhookCatalogSnapshot
{
    public static WebhookCatalogSnapshot Empty { get; } = new([]);

    private readonly Dictionary<int, ActiveWebhook> _byId;

    public WebhookCatalogSnapshot(IReadOnlyList<ActiveWebhook> webhooks)
    {
        _byId = webhooks.ToDictionary(w => w.Id);
        Async = webhooks.Where(w => !w.Definition.Sync && !w.Definition.OnlyForEventRules).ToArray();
        Sync = webhooks.Where(w => w.Definition.Sync && !w.Definition.OnlyForEventRules).ToArray();
    }

    /// <summary>The asynchronous webhooks that get the events of their filters (not the ones only for event rules).</summary>
    public IReadOnlyList<ActiveWebhook> Async { get; }

    public IReadOnlyList<ActiveWebhook> Sync { get; }

    /// <summary>Any enabled webhook, also one only for event rules.</summary>
    public ActiveWebhook? Find(int id) => _byId.GetValueOrDefault(id);

    /// <summary>Any enabled webhook by its name (case-insensitive).</summary>
    public ActiveWebhook? Find(string name) => _byId.Values.FirstOrDefault(w => string.Equals(w.Name, name, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// The enabled webhooks in memory, so that an event costs no database read: with no webhook, the sink and the hook
/// return at once. It is loaded at the first use, reloaded after each change in the admin UI and every 30 s by the
/// dispatcher, and with several nodes (#75) when the settings version changed (<see cref="ISettingsChangeNotifier"/>).
/// </summary>
public sealed class WebhookCatalog
{
    private readonly IWebhookStore _store;
    private readonly WebhookSecretProtector _protector;
    private readonly WebhookOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _loadLock = new(1, 1);
    private volatile WebhookCatalogSnapshot? _current;
    private long _loadedAt;

    public WebhookCatalog(IWebhookStore store, WebhookSecretProtector protector, IOptions<WebhookOptions> options, TimeProvider time,
        ILogger<WebhookCatalog> logger, ISettingsChangeNotifier? changes = null)
    {
        _store = store;
        _protector = protector;
        _options = options.Value;
        _time = time;
        _logger = logger;
        if (changes != null)
            changes.Changed += () => _ = ReloadAfterChangeAsync();
    }

    /// <summary>Another node changed the settings: reload, when the webhooks were loaded already.</summary>
    private async Task ReloadAfterChangeAsync()
    {
        if (_current == null)
            return;
        try
        {
            await ReloadAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not reload the webhooks after a change of the settings.");
        }
    }

    /// <summary>The time since the last load; null before the first load.</summary>
    public TimeSpan? Age => _current == null ? null : _time.GetElapsedTime(Interlocked.Read(ref _loadedAt));

    /// <summary>The current webhooks; loads them at the first call.</summary>
    public ValueTask<WebhookCatalogSnapshot> GetAsync(CancellationToken ct)
        => _current is { } current ? ValueTask.FromResult(current) : new ValueTask<WebhookCatalogSnapshot>(LoadFirstAsync(ct));

    private async Task<WebhookCatalogSnapshot> LoadFirstAsync(CancellationToken ct)
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

    /// <summary>Reads the webhooks from the store again.</summary>
    public async Task<WebhookCatalogSnapshot> ReloadAsync(CancellationToken ct)
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

    private async Task<WebhookCatalogSnapshot> LoadAsync(CancellationToken ct)
    {
        WebhookCatalogSnapshot snapshot;
        if (!_store.IsEnabled)
        {
            snapshot = WebhookCatalogSnapshot.Empty;
        }
        else
        {
            var webhooks = await _store.ListAsync(ct);
            snapshot = new WebhookCatalogSnapshot(webhooks.Where(w => w.Enabled).Select(Activate).ToArray());
        }
        Interlocked.Exchange(ref _loadedAt, _time.GetTimestamp());
        _current = snapshot;
        return snapshot;
    }

    private ActiveWebhook Activate(Webhook webhook)
    {
        // The URL rule again: the operator can turn AllowInsecureWebhooks off after an http:// webhook was saved.
        if (WebhookValidator.ValidateUrl(webhook.Url, _options) is { } urlError)
        {
            _logger.LogError("The webhook {Webhook} is not sent: {Error}", webhook.Name, urlError);
            return new ActiveWebhook(webhook, null, urlError);
        }
        if (string.IsNullOrEmpty(webhook.ProtectedSecret))
            return new ActiveWebhook(webhook, null, null);
        var secret = _protector.TryUnprotect(webhook.ProtectedSecret);
        if (secret != null)
            return new ActiveWebhook(webhook, secret, null);

        _logger.LogError("The secret of the webhook {Webhook} cannot be decrypted (the data protection keys changed?). " +
            "Its requests are not sent until a new secret is set.", webhook.Name);
        return new ActiveWebhook(webhook, null, "The secret cannot be decrypted; set a new secret.");
    }
}
