using LiteDB;
using SshServer.Interfaces;

namespace SshServer.Settings.LiteDb;

/// <summary>
/// The contents of a LiteDB settings file: the server settings (with the host key) and all users.
/// </summary>
public sealed record LiteDbSettingsSnapshot(ServerSettings? ServerSettings, List<User> Users);

/// <summary>
/// Reads a LiteDB settings file (the old "config.db") without changing it. Used for the one-time import
/// into the SQL settings database.
/// </summary>
public static class LiteDbSettingsReader
{
    public static LiteDbSettingsSnapshot Read(string databasePath)
    {
        if (!File.Exists(databasePath))
            throw new FileNotFoundException("The LiteDB settings file does not exist.", databasePath);

        var connectionString = new ConnectionString
        {
            Filename = databasePath,
            ReadOnly = true,
            Connection = ConnectionType.Direct,
        };

        using var db = new LiteDatabase(connectionString);

        ServerSettings? settings = null;
        if (db.CollectionExists("settings"))
        {
            var stored = db.GetCollection<FxSsh.SshServerModule.ServerSettingsWithObjectId>("settings")
                .FindOne(s => s.ServerRsaKey != null);
            if (stored != null)
            {
                settings = new ServerSettings
                {
                    ServerRsaKey = stored.ServerRsaKey,
                    ServerEcdsaKey = stored.ServerEcdsaKey, // only in files written by a version with ECDSA host keys
                    ServerBanner = stored.ServerBanner,
                    ListenToPort = stored.ListenToPort,
                    ServerRootDirectory = stored.ServerRootDirectory,
                    BindToAddress = stored.BindToAddress,
                    BlacklistedIps = stored.BlacklistedIps,
                    MaxLoginAttemptsBeforeBan = stored.MaxLoginAttemptsBeforeBan,
                    IdleTimeout = stored.IdleTimeout,
                    EnableCommand = stored.EnableCommand,
                    EnableDirectTcpIp = stored.EnableDirectTcpIp,
                };
            }
        }

        var users = new List<User>();
        if (db.CollectionExists("users"))
        {
            foreach (var stored in db.GetCollection<FxSsh.SshServerModule.UserWithObjectId>("users").FindAll())
            {
                users.Add(new User
                {
                    Username = stored.Username,
                    UserRootDirectory = stored.UserRootDirectory,
                    HashedPassword = stored.HashedPassword,
                    RsaPublicKey = stored.RsaPublicKey,
                    OnlyWhitelistedIps = stored.OnlyWhitelistedIps,
                    WhitelistedIps = stored.WhitelistedIps,
                    LastSuccessfulLogin = stored.LastSuccessfulLogin,
                });
            }
        }

        return new LiteDbSettingsSnapshot(settings, users);
    }
}
