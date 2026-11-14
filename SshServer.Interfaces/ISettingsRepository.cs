using System.Collections.Generic;
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

    /// <summary>Removes the folder and unmounts it from every user. False when there is no such folder.</summary>
    bool RemoveVirtualFolder(int id);
}