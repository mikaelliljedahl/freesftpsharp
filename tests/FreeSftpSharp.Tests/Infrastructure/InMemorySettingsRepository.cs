using System.Collections.Concurrent;
using SshServer.Interfaces;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Storage;

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

    private readonly ConcurrentDictionary<int, VirtualFolder> _folders = new();
    private int _nextFolderId;

    public List<VirtualFolder> GetVirtualFolders() => _folders.Values.OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase).Select(Copy).ToList();

    public VirtualFolder? GetVirtualFolder(int id) => _folders.TryGetValue(id, out var folder) ? Copy(folder) : null;

    public bool AddVirtualFolder(VirtualFolder folder)
    {
        if (string.IsNullOrWhiteSpace(folder.Name) || _folders.Values.Any(f => string.Equals(f.Name, folder.Name, StringComparison.OrdinalIgnoreCase)))
            return false;
        folder.Id = Interlocked.Increment(ref _nextFolderId);
        _folders[folder.Id] = Copy(folder);
        return true;
    }

    public bool UpdateVirtualFolder(VirtualFolder folder)
    {
        if (!_folders.ContainsKey(folder.Id)
            || _folders.Values.Any(f => f.Id != folder.Id && string.Equals(f.Name, folder.Name, StringComparison.OrdinalIgnoreCase)))
            return false;
        _folders[folder.Id] = Copy(folder);
        return true;
    }

    public bool RemoveVirtualFolder(int id)
    {
        if (!_folders.TryRemove(id, out _))
            return false;
        foreach (var user in _users.Values)
            user.VirtualFolders.RemoveAll(m => m.VirtualFolderId == id);
        foreach (var group in _groups.Values)
            group.VirtualFolders.RemoveAll(m => m.VirtualFolderId == id);
        return true;
    }

    private readonly ConcurrentDictionary<int, Group> _groups = new();
    private int _nextGroupId;

    public List<Group> GetGroups() => _groups.Values.OrderBy(g => g.Name, StringComparer.OrdinalIgnoreCase).Select(g => g.Clone()).ToList();

    public Group? GetGroup(int id) => _groups.TryGetValue(id, out var group) ? group.Clone() : null;

    public bool AddGroup(Group group)
    {
        if (string.IsNullOrWhiteSpace(group.Name) || _groups.Values.Any(g => string.Equals(g.Name, group.Name, StringComparison.OrdinalIgnoreCase)))
            return false;
        group.Id = Interlocked.Increment(ref _nextGroupId);
        _groups[group.Id] = group.Clone();
        return true;
    }

    public bool UpdateGroup(Group group)
    {
        if (!_groups.ContainsKey(group.Id)
            || _groups.Values.Any(g => g.Id != group.Id && string.Equals(g.Name, group.Name, StringComparison.OrdinalIgnoreCase)))
            return false;
        _groups[group.Id] = group.Clone();
        return true;
    }

    public bool RemoveGroup(int id) =>
        !_users.Values.Any(u => GroupService.IsMember(u, id)) && _groups.TryRemove(id, out _);

    private static VirtualFolder Copy(VirtualFolder folder) => new() { Id = folder.Id, Name = folder.Name, Description = folder.Description, Storage = folder.Storage };

    public void Dispose()
    {
    }
}
