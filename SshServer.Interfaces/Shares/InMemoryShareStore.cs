namespace SshServer.Interfaces.Shares;

/// <summary>The share store in memory: for the obsolete LiteDB settings provider (the shares are lost at a restart) and for tests.</summary>
public sealed class InMemoryShareStore : IShareStore
{
    private readonly object _lock = new();
    private readonly Dictionary<string, Share> _shares = new(StringComparer.Ordinal);

    public Task<IReadOnlyList<Share>> ListAsync(int? userId, CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult<IReadOnlyList<Share>>(_shares.Values.Where(s => userId == null || s.UserId == userId)
                .OrderByDescending(s => s.CreatedAt).Select(s => s.Clone()).ToList());
    }

    public Task<Share?> GetAsync(string id, CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult(_shares.TryGetValue(id, out var share) ? share.Clone() : null);
    }

    public Task AddAsync(Share share, CancellationToken ct)
    {
        lock (_lock)
        {
            if (!_shares.TryAdd(share.Id, share.Clone()))
                throw new InvalidOperationException("A share with this id exists.");
        }
        return Task.CompletedTask;
    }

    public Task<bool> RemoveAsync(string id, CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult(_shares.Remove(id));
    }

    public Task<bool> TryUseAsync(string id, DateTime usedAtUtc, CancellationToken ct)
    {
        lock (_lock)
        {
            if (!_shares.TryGetValue(id, out var share) || (share.MaxUses > 0 && share.UsedCount >= share.MaxUses))
                return Task.FromResult(false);
            share.UsedCount++;
            share.LastUsedAt = usedAtUtc;
            return Task.FromResult(true);
        }
    }
}
