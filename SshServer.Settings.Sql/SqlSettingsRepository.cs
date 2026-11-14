using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Interfaces;
using SshServer.Interfaces.Events;
using SshServer.Settings.LiteDb;

namespace SshServer.Settings.Sql;

/// <summary>
/// <see cref="ISettingsRepository"/> on EF Core. The provider (SQLite today) comes from the
/// <see cref="DbContextOptions{TContext}"/>. Each call uses its own short-lived <see cref="SettingsDbContext"/>,
/// so the singleton repository is safe to use from the SSH sessions and the admin UI at the same time.
/// The returned objects are detached copies: change them and call the Update methods to save.
/// <para>
/// Every saved change of a user or of the server settings is published as a <see cref="ProviderEvent"/>, without
/// secrets. An update that changes only <see cref="User.LastSuccessfulLogin"/> (each login) gives no event.
/// </para>
/// </summary>
public sealed class SqlSettingsRepository : ISettingsRepository, IDisposable
{
    private readonly DbContextOptions<SettingsDbContext> _options;
    private readonly ILogger _logger;
    private readonly IEventBus? _events;
    private readonly TimeProvider _time;

    /// <param name="options">The EF Core options (provider and connection).</param>
    /// <param name="logger">The logger.</param>
    /// <param name="legacyLiteDbPath">A LiteDB file to import once when the SQL database is new. Null: no import.</param>
    /// <param name="createHostKey">Makes a new host key when there is nothing to import. Default: RSA 4096 (as before).</param>
    /// <param name="events">The event bus for the provider events. Null: no events.</param>
    /// <param name="time">The clock of the events. Null: the system clock.</param>
    public SqlSettingsRepository(
        DbContextOptions<SettingsDbContext> options,
        ILogger<SqlSettingsRepository>? logger = null,
        string? legacyLiteDbPath = null,
        Func<string>? createHostKey = null,
        IEventBus? events = null,
        TimeProvider? time = null)
    {
        _options = options;
        _logger = (ILogger?)logger ?? NullLogger.Instance;
        _events = events;
        _time = time ?? TimeProvider.System;
        Initialize(legacyLiteDbPath, createHostKey ?? CreateDefaultHostKey);
    }

    private SettingsDbContext CreateContext() => new(_options);

    private void Initialize(string? legacyLiteDbPath, Func<string> createHostKey)
    {
        using var db = CreateContext();

        // A database without applied migrations is new (or empty). Only then is the LiteDB file imported.
        var isNew = !db.Database.GetAppliedMigrations().Any();
        db.Database.Migrate();

        if (isNew && !string.IsNullOrEmpty(legacyLiteDbPath) && File.Exists(legacyLiteDbPath)
            && !db.ServerSettings.Any() && !db.Users.Any())
        {
            ImportFromLiteDb(db, legacyLiteDbPath);
        }

        if (!db.ServerSettings.Any())
        {
            db.ServerSettings.Add(new ServerSettings
            {
                ServerRsaKey = createHostKey(),
                ListenToPort = 22, // default port, as in the LiteDB repository
            });
            db.SaveChanges();
            _logger.LogInformation("Created new server settings with a new host key in the settings database");
        }
    }

    private void ImportFromLiteDb(SettingsDbContext db, string liteDbPath)
    {
        var snapshot = LiteDbSettingsReader.Read(liteDbPath);

        if (snapshot.ServerSettings != null)
        {
            snapshot.ServerSettings.Id = 0;
            db.ServerSettings.Add(snapshot.ServerSettings);
        }

        foreach (var user in snapshot.Users.Where(u => !string.IsNullOrEmpty(u.Username)))
        {
            user.Id = 0;
            db.Users.Add(user);
        }

        db.SaveChanges();
        _logger.LogWarning(
            "Imported the server settings{HostKey} and {UserCount} user(s) from the LiteDB file {LiteDbPath} into the settings database. The LiteDB file was not changed and is no longer used",
            snapshot.ServerSettings != null ? " (with the host key)" : "",
            snapshot.Users.Count,
            liteDbPath);
    }

    private static string CreateDefaultHostKey()
    {
        using var csp = new RSACryptoServiceProvider(4096);
        return Convert.ToBase64String(csp.ExportCspBlob(true));
    }

    public ServerSettings ServerSettings
    {
        get
        {
            using var db = CreateContext();
            return db.ServerSettings.AsNoTracking().OrderBy(s => s.Id).First();
        }
    }

    public bool UpdateServerSettings(ServerSettings updatedSettings)
    {
        using var db = CreateContext();
        var stored = db.ServerSettings.OrderBy(s => s.Id).FirstOrDefault();
        if (stored == null)
            return false;

        var before = ServerSettingsSnapshot.From(stored);
        var keysBefore = (stored.ServerRsaKey, stored.ServerEcdsaKey);
        stored.ServerRsaKey = updatedSettings.ServerRsaKey;
        // Never drop the saved ECDSA host key: a caller that does not know the field sends it empty.
        if (!string.IsNullOrWhiteSpace(updatedSettings.ServerEcdsaKey))
            stored.ServerEcdsaKey = updatedSettings.ServerEcdsaKey;
        stored.ServerBanner = updatedSettings.ServerBanner;
        stored.ListenToPort = updatedSettings.ListenToPort;
        stored.BindToAddress = updatedSettings.BindToAddress;
        stored.BlacklistedIps = updatedSettings.BlacklistedIps;
        stored.OnlyWhitelistedIps = updatedSettings.OnlyWhitelistedIps;
        stored.WhitelistedIps = updatedSettings.WhitelistedIps;
        stored.MaxLoginAttemptsBeforeBan = updatedSettings.MaxLoginAttemptsBeforeBan;
        stored.LoginFailureWindowSeconds = updatedSettings.LoginFailureWindowSeconds;
        stored.BanDurationSeconds = updatedSettings.BanDurationSeconds;
        stored.ExemptLoopbackFromBan = updatedSettings.ExemptLoopbackFromBan;
        stored.IdleTimeout = updatedSettings.IdleTimeout;
        stored.EnableCommand = updatedSettings.EnableCommand;
        stored.EnableDirectTcpIp = updatedSettings.EnableDirectTcpIp;
        db.SaveChanges();

        var changed = ChangedFields(before, ServerSettingsSnapshot.From(stored));
        if (keysBefore != (stored.ServerRsaKey, stored.ServerEcdsaKey))
            changed.Add("HostKey");
        if (changed.Count > 0)
            Publish(new ProviderEvent(ProviderAction.Update, ProviderObjectType.ServerSettings, "server")
            {
                Object = ServerSettingsSnapshot.From(stored),
                ChangedFields = changed,
            });
        return true;
    }

    /// <summary>Returns the user, or null when there is no user with that name.</summary>
    public User GetUser(string username)
    {
        using var db = CreateContext();
        return db.Users.AsNoTracking().FirstOrDefault(u => u.Username == username)!;
    }

    public bool RemoveUser(string username)
    {
        using var db = CreateContext();
        var stored = db.Users.FirstOrDefault(u => u.Username == username);
        if (stored == null)
            return false;
        db.Users.Remove(stored);
        db.SaveChanges();
        Publish(new ProviderEvent(ProviderAction.Delete, ProviderObjectType.User, stored.Username) { Object = UserSnapshot.From(stored) });
        return true;
    }

    public List<User> GetAllUsers()
    {
        using var db = CreateContext();
        return db.Users.AsNoTracking().OrderBy(u => u.Id).ToList();
    }

    /// <summary>Adds a copy of the user. Returns false when the username is empty or already exists.</summary>
    public bool AddUser(User newUser)
    {
        if (string.IsNullOrEmpty(newUser.Username))
            return false;

        using var db = CreateContext();
        if (db.Users.Any(u => u.Username == newUser.Username))
            return false;

        var stored = new User
        {
            Username = newUser.Username,
            UserRootDirectory = newUser.UserRootDirectory,
            HashedPassword = newUser.HashedPassword,
            RsaPublicKey = newUser.RsaPublicKey,
            OnlyWhitelistedIps = newUser.OnlyWhitelistedIps,
            WhitelistedIps = newUser.WhitelistedIps,
            LastSuccessfulLogin = newUser.LastSuccessfulLogin,
        };
        db.Users.Add(stored);
        db.SaveChanges();
        newUser.Id = stored.Id;
        Publish(new ProviderEvent(ProviderAction.Add, ProviderObjectType.User, stored.Username) { Object = UserSnapshot.From(stored) });
        return true;
    }

    /// <summary>Updates the user with the same username. Returns false when there is no such user.</summary>
    public bool UpdateUser(User updatedUser)
    {
        using var db = CreateContext();
        var stored = db.Users.FirstOrDefault(u => u.Username == updatedUser.Username);
        if (stored == null)
            return false;

        var before = UserSnapshot.From(stored);
        var passwordChanged = stored.HashedPassword != updatedUser.HashedPassword;
        var keyChanged = stored.RsaPublicKey != updatedUser.RsaPublicKey;
        stored.HashedPassword = updatedUser.HashedPassword;
        stored.LastSuccessfulLogin = updatedUser.LastSuccessfulLogin;
        stored.OnlyWhitelistedIps = updatedUser.OnlyWhitelistedIps;
        stored.RsaPublicKey = updatedUser.RsaPublicKey;
        stored.UserRootDirectory = updatedUser.UserRootDirectory;
        stored.WhitelistedIps = updatedUser.WhitelistedIps;
        db.SaveChanges();

        var changed = ChangedFields(before, UserSnapshot.From(stored));
        // The snapshot tells only whether there is a password or key; a new one is a change too.
        if (passwordChanged && !changed.Contains(nameof(UserSnapshot.HasPassword)))
            changed.Add("Password");
        if (keyChanged && !changed.Contains(nameof(UserSnapshot.HasPublicKey)))
            changed.Add("PublicKey");
        if (changed.Count > 0)
            Publish(new ProviderEvent(ProviderAction.Update, ProviderObjectType.User, stored.Username)
            {
                Object = UserSnapshot.From(stored),
                ChangedFields = changed,
            });
        return true;
    }

    /// <summary>The names of the properties with different values; lists are compared by their items.</summary>
    private static List<string> ChangedFields<T>(T before, T after)
    {
        var changed = new List<string>();
        foreach (var property in typeof(T).GetProperties())
        {
            var a = property.GetValue(before);
            var b = property.GetValue(after);
            var same = a is IEnumerable<string> listA && b is IEnumerable<string> listB ? listA.SequenceEqual(listB) : Equals(a, b);
            if (!same)
                changed.Add(property.Name);
        }
        return changed;
    }

    /// <summary>Publishes a provider event. The actor is not known here (null) until the admin identity comes (#67).</summary>
    private void Publish(ProviderEvent @event)
    {
        if (_events == null)
            return;
        try
        {
            var publish = _events.PublishAsync(@event with { Timestamp = _time.GetUtcNow() });
            if (!publish.IsCompletedSuccessfully)
                publish.AsTask().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            // The change is saved; only its event is lost.
            _logger.LogError(ex, "Could not publish the {Action} event of {ObjectType} {Name}.", @event.Action, @event.ObjectType, @event.ObjectName);
        }
    }

    public void Dispose()
    {
        // Nothing to release: every call disposes its own DbContext.
    }
}
