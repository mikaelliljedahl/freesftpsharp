using System.Collections.Concurrent;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.Infrastructure;

/// <summary>
/// An <see cref="ISettingsRepository"/> that keeps everything in memory. The tests use it instead of the
/// real settings repository (SQLite), so the end-to-end tests need no database file.
/// </summary>
public sealed class InMemorySettingsRepository : ISettingsRepository
{
    private readonly ConcurrentDictionary<string, User> _users = new(StringComparer.Ordinal);
    private ServerSettings _serverSettings;
    private int _lastId;

    public InMemorySettingsRepository(ServerSettings serverSettings)
    {
        _serverSettings = serverSettings;
    }

    public ServerSettings ServerSettings => _serverSettings;

    public bool UpdateServerSettings(ServerSettings updatedSettings)
    {
        _serverSettings = updatedSettings;
        return true;
    }

    // The interface returns null for an unknown user (HostedServer checks for null).
    public User GetUser(string username) => _users.TryGetValue(username, out var user) ? user : null!;

    public bool RemoveUser(string username) => _users.TryRemove(username, out _);

    public List<User> GetAllUsers() => _users.Values.ToList();

    /// <summary>Adds the user; a user without an id gets the next one, like the database (the second factor uses it).</summary>
    public bool AddUser(User newUser)
    {
        if (_users.ContainsKey(newUser.Username))
            return false;
        if (newUser.Id == 0)
            newUser.Id = Interlocked.Increment(ref _lastId);
        return _users.TryAdd(newUser.Username, newUser);
    }

    public bool UpdateUser(User updatedUser)
    {
        if (!_users.ContainsKey(updatedUser.Username))
            return false;
        _users[updatedUser.Username] = updatedUser;
        return true;
    }

    public void Dispose()
    {
    }
}
