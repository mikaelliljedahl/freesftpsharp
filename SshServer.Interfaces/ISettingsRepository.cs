using System.Collections.Generic;

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
}