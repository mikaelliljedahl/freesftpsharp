using System.Collections.Generic;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Storage;

namespace SshServer.Interfaces;

public interface ISettingsRepository
{
    void Dispose();
    ServerSettings ServerSettings { get; }
    bool UpdateServerSettings(ServerSettings updatedSettings);
    User GetUser(string username);
    bool RemoveUser(string username);
    List<User> GetAllUsers();
    bool AddUser(User newUser);
    bool UpdateUser(User updatedUser);

    /// <summary>Every virtual folder, ordered by name.</summary>
    List<VirtualFolder> GetVirtualFolders();

    /// <summary>The virtual folder with this id, or null.</summary>
    VirtualFolder? GetVirtualFolder(int id);

    /// <summary>Adds a copy of the folder and sets its <see cref="VirtualFolder.Id"/>. False when the name is empty or already used (without case).</summary>
    bool AddVirtualFolder(VirtualFolder folder);

    /// <summary>Updates the folder with the same id. False when there is no such folder or the new name is used by another one.</summary>
    bool UpdateVirtualFolder(VirtualFolder folder);

    /// <summary>Removes the folder and unmounts it from every user and group. False when there is no such folder.</summary>
    bool RemoveVirtualFolder(int id);

    /// <summary>Every group (issue #61), ordered by name.</summary>
    List<Group> GetGroups();

    /// <summary>A copy of the group with this id, or null.</summary>
    Group? GetGroup(int id);

    /// <summary>Adds a copy of the group and sets its <see cref="Group.Id"/>. False when the name is empty or already used (without case).</summary>
    bool AddGroup(Group group);

    /// <summary>Updates the group with the same id. False when there is no such group or the new name is used by another one.</summary>
    bool UpdateGroup(Group group);

    /// <summary>
    /// Removes the group. False when there is no such group or a user is still a member (the caller removes the
    /// members first, so no user loses or gains settings silently).
    /// </summary>
    bool RemoveGroup(int id);
}