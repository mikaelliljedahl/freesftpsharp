using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using LiteDB;
using SshServer.Interfaces;


namespace FxSsh.SshServerModule
{
    public class ServerSettingsWithObjectId : ServerSettings
    {
        public new ObjectId Id { get; set; } = ObjectId.Empty;
        public ServerSettings MapToServerSettings()
        {
            var user = (ServerSettings)this;
            user.Id = this.Id.GetHashCode();
            return user;
        }
    }

    public class UserWithObjectId : User
    {
        public new ObjectId Id { get; set; } = ObjectId.Empty;

        /// <summary>
        /// The single key of a user in files of versions before issue #58 (a base64 CSP blob). The import into the SQL
        /// database (<see cref="SshServer.Settings.LiteDb.LiteDbSettingsReader"/>) converts it to a key entry.
        /// </summary>
        public string? RsaPublicKey { get; set; }

        public User MapToUser()
        {
            var user = (User)this;
            user.Id = this.Id.GetHashCode();
            return user;
        }

        public UserWithObjectId(User user)
        {
            this.Username = user.Username;
            this.HashedPassword = user.HashedPassword;
            this.LastSuccessfulLogin = user.LastSuccessfulLogin;
            this.OnlyWhitelistedIps = user.OnlyWhitelistedIps;
            this.PublicKeys = user.PublicKeys;
            this.AllowedAuthMethods = user.AllowedAuthMethods;
            this.RequireAllOf = user.RequireAllOf;
            this.UserRootDirectory = user.UserRootDirectory;
            this.WhitelistedIps = user.WhitelistedIps;
            this.Permissions = user.Permissions;
            this.PathFilters = user.PathFilters;
            this.Id = new ObjectId();
        }

        public UserWithObjectId()
        {
        }
    }


    public class SettingsRepository : IDisposable, ISettingsRepository
    {
        public void Dispose()
        {
            if (db != null)
                db.Dispose();
        }

        private LiteDatabase db;
        private ILiteCollection<ServerSettingsWithObjectId> serversettingsCollection;

        ServerSettingsWithObjectId _serverSettings { get; set; }

        ServerSettings ISettingsRepository.ServerSettings => _serverSettings.MapToServerSettings();
            
        public bool UpdateServerSettings(ServerSettings UpdatedSettings)
        {
            var serversettings = db.GetCollection<ServerSettingsWithObjectId>("settings");

            _serverSettings = serversettings.FindOne(s => s.ServerRsaKey != null);

            _serverSettings.BindToAddress = UpdatedSettings.BindToAddress;
            _serverSettings.BlacklistedIps = UpdatedSettings.BlacklistedIps;
            _serverSettings.EnableCommand = UpdatedSettings.EnableCommand;
            _serverSettings.EnableDirectTcpIp = UpdatedSettings.EnableDirectTcpIp;
            _serverSettings.IdleTimeout = UpdatedSettings.IdleTimeout;
            _serverSettings.ListenToPort = UpdatedSettings.ListenToPort;
            _serverSettings.MaxLoginAttemptsBeforeBan = UpdatedSettings.MaxLoginAttemptsBeforeBan;
            _serverSettings.OnlyWhitelistedIps = UpdatedSettings.OnlyWhitelistedIps;
            _serverSettings.WhitelistedIps = UpdatedSettings.WhitelistedIps;
            _serverSettings.LoginFailureWindowSeconds = UpdatedSettings.LoginFailureWindowSeconds;
            _serverSettings.BanDurationSeconds = UpdatedSettings.BanDurationSeconds;
            _serverSettings.ExemptLoopbackFromBan = UpdatedSettings.ExemptLoopbackFromBan;
            _serverSettings.ServerRsaKey = UpdatedSettings.ServerRsaKey;
            if (!string.IsNullOrWhiteSpace(UpdatedSettings.ServerEcdsaKey)) // never drop the saved key
                _serverSettings.ServerEcdsaKey = UpdatedSettings.ServerEcdsaKey;

            return serversettings.Update(_serverSettings);
        }

        public User GetUser(string Username)
        {
            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<UserWithObjectId>("users");

            return usercol.FindOne(x => x.Username == Username);

        }
        public bool RemoveUser(string Username)
        {
            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<UserWithObjectId>("users");

            var usertoremove = usercol.FindOne(x => x.Username == Username);

            return usercol.Delete(usertoremove.Id);

        }
        

        public List<User> GetAllUsers()
        {
            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<UserWithObjectId>("users");

            return usercol.FindAll().ToList().Select(u => u.MapToUser()).ToList();

        }

        public bool AddUser(User NewUser)
        {
            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<UserWithObjectId>("users");

            usercol.Insert(new UserWithObjectId(NewUser));

            return true;

        }


        public bool UpdateUser(User UpdatedUser)
        {
            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<UserWithObjectId>("users");

            var user = usercol.FindOne(x => x.Username == UpdatedUser.Username);
           

            user.HashedPassword = UpdatedUser.HashedPassword;
            user.LastSuccessfulLogin = UpdatedUser.LastSuccessfulLogin;
            user.OnlyWhitelistedIps = UpdatedUser.OnlyWhitelistedIps;
            user.PublicKeys = UpdatedUser.PublicKeys;
            user.AllowedAuthMethods = UpdatedUser.AllowedAuthMethods;
            user.RequireAllOf = UpdatedUser.RequireAllOf;
            user.UserRootDirectory = UpdatedUser.UserRootDirectory;
            user.WhitelistedIps = UpdatedUser.WhitelistedIps;
            user.Permissions = UpdatedUser.Permissions;
            user.PathFilters = UpdatedUser.PathFilters;
            return usercol.Update(user);
            
        }

        /// <summary>The legacy default: "config.db" in the current directory.</summary>
        public const string DefaultFileName = "config.db";

        public SettingsRepository() : this(DefaultFileName)
        {
        }

        public SettingsRepository(string databasePath)
        {
            db = new LiteDatabase(databasePath);

            serversettingsCollection = db.GetCollection<ServerSettingsWithObjectId>("settings");

            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<UserWithObjectId>("users");

            // Index users using username property
            usercol.EnsureIndex(x => x.Username, true);

            // Issue #58: move the old single key of each user to the key list.
            foreach (var legacy in usercol.Find(u => u.RsaPublicKey != null).ToList())
            {
                legacy.PublicKeys = SshServer.Settings.LiteDb.LiteDbSettingsReader.PublicKeysOf(legacy);
                legacy.RsaPublicKey = null;
                usercol.Update(legacy);
            }

            _serverSettings = serversettingsCollection.FindOne(s=>s.ServerRsaKey != null);
            

            if (_serverSettings == null)
            {
                // Insert new settings document (Id will be auto-incremented)
                _serverSettings = new ServerSettingsWithObjectId();

                var csp = new System.Security.Cryptography.RSACryptoServiceProvider(4096);

                var rsakeydata = csp.ExportCspBlob(true);
                _serverSettings.ServerRsaKey = Convert.ToBase64String( rsakeydata );
                _serverSettings.ListenToPort = 22; // default port

                serversettingsCollection.Insert(_serverSettings);

            }

        }
    }
}