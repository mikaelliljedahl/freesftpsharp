namespace FreeSftpSharp.WebDav;

/// <summary>A WebDAV write lock (RFC 4918 section 6).</summary>
/// <param name="Token">The lock token, "urn:uuid:...".</param>
/// <param name="Owner">The user whose namespace has the lock.</param>
/// <param name="Root">The virtual path of the locked resource.</param>
/// <param name="Exclusive">An exclusive lock; otherwise shared.</param>
/// <param name="Infinite">Depth infinity: the lock covers every member of a collection.</param>
/// <param name="OwnerXml">The DAV:owner element that the client sent, or null.</param>
/// <param name="Timeout">The timeout of the lock.</param>
/// <param name="ExpiresAt">When the lock ends unless it is refreshed.</param>
internal sealed record WebDavLock(string Token, string Owner, string Root, bool Exclusive, bool Infinite, string? OwnerXml,
    TimeSpan Timeout, DateTimeOffset ExpiresAt);

/// <summary>
/// The WebDAV locks, in memory with timeouts (a restart forgets them; enough for the Windows, macOS and office clients).
/// The locks of each user are separate: the lock namespace is the user's own file tree. Thread safe (one lock).
/// </summary>
internal sealed class WebDavLockManager
{
    private readonly object _sync = new();
    private readonly List<WebDavLock> _locks = new();
    private readonly TimeProvider _time;

    public WebDavLockManager(TimeProvider time)
    {
        _time = time;
    }

    /// <summary>The locks that cover <paramref name="path"/>: on the path itself, or depth infinity on a parent.</summary>
    public IReadOnlyList<WebDavLock> Covering(string owner, string path)
    {
        lock (_sync)
        {
            RemoveExpired();
            return _locks.Where(l => l.Owner == owner && Covers(l, path)).ToList();
        }
    }

    /// <summary>The locks on <paramref name="path"/> or on a member of it.</summary>
    public IReadOnlyList<WebDavLock> Within(string owner, string path)
    {
        lock (_sync)
        {
            RemoveExpired();
            return _locks.Where(l => l.Owner == owner && IsSameOrUnder(l.Root, path)).ToList();
        }
    }

    /// <summary>
    /// Adds a lock, or returns the lock that conflicts with it (an exclusive lock conflicts with every other lock on the
    /// same resource, a shared one with exclusive locks).
    /// </summary>
    public (WebDavLock? Created, WebDavLock? Conflict) TryLock(string owner, string path, bool exclusive, bool infinite, string? ownerXml, TimeSpan timeout)
    {
        lock (_sync)
        {
            RemoveExpired();
            var conflict = _locks.FirstOrDefault(l => l.Owner == owner
                && (Covers(l, path) || (infinite && IsSameOrUnder(l.Root, path)))
                && (exclusive || l.Exclusive));
            if (conflict != null)
                return (null, conflict);
            var created = new WebDavLock("urn:uuid:" + Guid.NewGuid().ToString("D"), owner, path, exclusive, infinite, ownerXml,
                timeout, _time.GetUtcNow() + timeout);
            _locks.Add(created);
            return (created, null);
        }
    }

    /// <summary>Gives a lock that covers <paramref name="path"/> a new timeout; null when no such lock has the token.</summary>
    public WebDavLock? Refresh(string owner, string path, string token, TimeSpan timeout)
    {
        lock (_sync)
        {
            RemoveExpired();
            var index = _locks.FindIndex(l => l.Owner == owner && l.Token == token && Covers(l, path));
            if (index < 0)
                return null;
            var refreshed = _locks[index] with { Timeout = timeout, ExpiresAt = _time.GetUtcNow() + timeout };
            _locks[index] = refreshed;
            return refreshed;
        }
    }

    /// <summary>Removes the lock with the token when it covers <paramref name="path"/>. False when there is none.</summary>
    public bool Unlock(string owner, string path, string token)
    {
        lock (_sync)
        {
            RemoveExpired();
            return _locks.RemoveAll(l => l.Owner == owner && l.Token == token && Covers(l, path)) > 0;
        }
    }

    /// <summary>Removes the locks of a resource and its members, after a DELETE or a MOVE of it.</summary>
    public void RemoveWithin(string owner, string path)
    {
        lock (_sync)
            _locks.RemoveAll(l => l.Owner == owner && IsSameOrUnder(l.Root, path));
    }

    private void RemoveExpired()
    {
        var now = _time.GetUtcNow();
        _locks.RemoveAll(l => l.ExpiresAt <= now);
    }

    private static bool Covers(WebDavLock l, string path) => l.Root == path || (l.Infinite && IsSameOrUnder(path, l.Root));

    /// <summary>True when <paramref name="path"/> is <paramref name="parent"/> or a member of it, at any depth.</summary>
    public static bool IsSameOrUnder(string path, string parent) =>
        path == parent || parent == "/" || path.StartsWith(parent + "/", StringComparison.Ordinal);
}
