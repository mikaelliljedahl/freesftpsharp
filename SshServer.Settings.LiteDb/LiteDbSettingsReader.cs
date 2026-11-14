using LiteDB;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;

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
                    BindToAddress = stored.BindToAddress,
                    BlacklistedIps = stored.BlacklistedIps,
                    MaxLoginAttemptsBeforeBan = stored.MaxLoginAttemptsBeforeBan,
                    // Not in files of older versions: then these are the defaults of ServerSettings.
                    OnlyWhitelistedIps = stored.OnlyWhitelistedIps,
                    WhitelistedIps = stored.WhitelistedIps,
                    LoginFailureWindowSeconds = stored.LoginFailureWindowSeconds,
                    BanDurationSeconds = stored.BanDurationSeconds,
                    ExemptLoopbackFromBan = stored.ExemptLoopbackFromBan,
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
                    PublicKeys = PublicKeysOf(stored),
                    AllowedAuthMethods = stored.AllowedAuthMethods,
                    RequireAllOf = stored.RequireAllOf,
                    OnlyWhitelistedIps = stored.OnlyWhitelistedIps,
                    WhitelistedIps = stored.WhitelistedIps,
                    LastSuccessfulLogin = stored.LastSuccessfulLogin,
                    // Not in files of older versions: then the default of User ("/" = All).
                    Permissions = stored.Permissions,
                    PathFilters = stored.PathFilters,
                });
            }
        }

        return new LiteDbSettingsSnapshot(settings, users);
    }

    /// <summary>
    /// The keys of a stored user: the old single key (a base64 CSP blob) becomes an entry. A key that cannot be read did
    /// not work before either and is left out.
    /// </summary>
    internal static List<PublicKeyEntry>? PublicKeysOf(FxSsh.SshServerModule.UserWithObjectId stored)
    {
        var keys = stored.PublicKeys?.ToList();
        if (string.IsNullOrWhiteSpace(stored.RsaPublicKey))
            return keys;
        try
        {
            var entry = SshPublicKey.FromLegacyCspBlob(stored.RsaPublicKey, DateTime.UtcNow);
            keys ??= new List<PublicKeyEntry>();
            if (!keys.Any(k => k.KeyBase64 == entry.KeyBase64))
                keys.Add(entry);
        }
        catch (PublicKeyFormatException)
        {
            // Not a key; nothing to import.
        }
        return keys;
    }
}
