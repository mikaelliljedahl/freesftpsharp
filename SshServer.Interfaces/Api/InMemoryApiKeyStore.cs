namespace SshServer.Interfaces.Api;

/// <summary>
/// The API key and signing key stores in memory: for the obsolete LiteDB settings provider (the keys are lost at a
/// restart) and for tests. The key of a removed administrator stays, but it is refused (its owner does not exist).
/// </summary>
public sealed class InMemoryApiKeyStore : IApiKeyStore, IApiSigningKeyStore
{
    private readonly object _lock = new();
    private readonly List<ApiKey> _keys = new();
    private int _nextId;
    private string? _signingKey;

    public Task<IReadOnlyList<ApiKey>> ListAsync(int? adminId, CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult<IReadOnlyList<ApiKey>>(_keys.Where(k => adminId == null || k.AdminId == adminId)
                .OrderBy(k => k.Id).Select(k => k.Clone()).ToList());
    }

    public Task<ApiKey?> GetAsync(int id, CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult(_keys.FirstOrDefault(k => k.Id == id)?.Clone());
    }

    public Task<ApiKey?> FindByHashAsync(string keyHash, CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult(_keys.FirstOrDefault(k => k.KeyHash == keyHash)?.Clone());
    }

    public Task<bool> AddAsync(ApiKey key, CancellationToken ct)
    {
        lock (_lock)
        {
            if (_keys.Any(k => k.AdminId == key.AdminId && string.Equals(k.Name, key.Name, StringComparison.OrdinalIgnoreCase)))
                return Task.FromResult(false);
            key.Id = ++_nextId;
            _keys.Add(key.Clone());
            return Task.FromResult(true);
        }
    }

    public Task<bool> RemoveAsync(int id, CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult(_keys.RemoveAll(k => k.Id == id) > 0);
    }

    public Task TouchAsync(int id, DateTime usedAtUtc, CancellationToken ct)
    {
        lock (_lock)
        {
            var key = _keys.FirstOrDefault(k => k.Id == id);
            if (key != null)
                key.LastUsedAt = usedAtUtc;
        }
        return Task.CompletedTask;
    }

    public Task<string> GetOrAddAsync(Func<string> create, CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult(_signingKey ??= create());
    }
}
