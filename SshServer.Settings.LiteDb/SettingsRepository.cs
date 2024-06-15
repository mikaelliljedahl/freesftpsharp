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
        public new ObjectId Id { get; set; }
        public ServerSettings MapToServerSettings()
        {
            var user = (ServerSettings)this;
            user.Id = this.Id.GetHashCode();
            return user;
        }
    }

    public class UserWithObjectId : User
    {
        public new ObjectId Id { get; set; }

        public User MapToUser()
        {
            var user = (User)this;
            user.Id = this.Id.GetHashCode();
            return user;
        }

        public UserWithObjectId(User user)
        {
            this.HashedPassword = user.HashedPassword;
            this.LastSuccessfulLogin = user.LastSuccessfulLogin;
            this.OnlyWhitelistedIps = user.OnlyWhitelistedIps;
            this.RsaPublicKey = user.RsaPublicKey;
            this.UserRootDirectory = user.UserRootDirectory;
            this.WhitelistedIps = user.WhitelistedIps;
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
            _serverSettings.ServerRootDirectory = UpdatedSettings.ServerRootDirectory;
            _serverSettings.ServerRsaKey = UpdatedSettings.ServerRsaKey;

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
            user.RsaPublicKey = UpdatedUser.RsaPublicKey;
            user.UserRootDirectory = UpdatedUser.UserRootDirectory;
            user.WhitelistedIps = UpdatedUser.WhitelistedIps;
            return usercol.Update(user);
            
        }

        public SettingsRepository()
        {
            db = new LiteDatabase("config.db");

            serversettingsCollection = db.GetCollection<ServerSettingsWithObjectId>("settings");

            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<UserWithObjectId>("users");

            // Index users using username property
            usercol.EnsureIndex(x => x.Username, true);

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