using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using LiteDB;


namespace FxSsh.SshServerModule
{
    public class SettingsRepository : IDisposable
    {
        public void Dispose()
        {
            if (db != null)
                db.Dispose();
        }

        private LiteDatabase db;
        private ILiteCollection<ServerSettings> serversettings;

        public ServerSettings ServerSettings { get; set; }
        
        public bool UpdateServerSettings(ServerSettings UpdatedSettings)
        {
            var serversettings = db.GetCollection<ServerSettings>("settings");


            ServerSettings = serversettings.FindOne(s => s.ServerRsaKey != null);

            ServerSettings.BindToAddress = UpdatedSettings.BindToAddress;
            ServerSettings.BlacklistedIps = UpdatedSettings.BlacklistedIps;
            ServerSettings.EnableCommand = UpdatedSettings.EnableCommand;
            ServerSettings.EnableDirectTcpIp = UpdatedSettings.EnableDirectTcpIp;
            ServerSettings.IdleTimeout = UpdatedSettings.IdleTimeout;
            ServerSettings.ListenToPort = UpdatedSettings.ListenToPort;
            ServerSettings.MaxLoginAttemptsBeforeBan = UpdatedSettings.MaxLoginAttemptsBeforeBan;
            ServerSettings.ServerRootDirectory = UpdatedSettings.ServerRootDirectory;
            ServerSettings.ServerRsaKey = UpdatedSettings.ServerRsaKey;

            return serversettings.Update(ServerSettings);
        }

        public User GetUser(string Username)
        {
            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<User>("users");

            return usercol.FindOne(x => x.Username == Username);

        }
        public bool RemoveUser(string Username)
        {
            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<User>("users");

            var usertoremove = usercol.FindOne(x => x.Username == Username);

            return usercol.Delete(usertoremove.Id);

        }
        

        public List<User> GetAllUsers()
        {
            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<User>("users");

            return usercol.FindAll().ToList();

        }

        public bool AddUser(User NewUser)
        {
            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<User>("users");

            usercol.Insert(NewUser);

            return true;

        }


        public bool UpdateUser(User UpdatedUser)
        {
            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<User>("users");

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

            serversettings = db.GetCollection<ServerSettings>("settings");

            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<User>("users");

            // Index users using username property
            usercol.EnsureIndex(x => x.Username, true);

            ServerSettings = serversettings.FindOne(s=>s.ServerRsaKey != null);
            

            if (ServerSettings == null)
            {
                // Insert new settings document (Id will be auto-incremented)
                ServerSettings = new ServerSettings();

                var csp = new System.Security.Cryptography.RSACryptoServiceProvider(4096);

                var rsakeydata = csp.ExportCspBlob(true);
                ServerSettings.ServerRsaKey = Convert.ToBase64String( rsakeydata );
                ServerSettings.ListenToPort = 22; // default port

                serversettings.Insert(ServerSettings);

            }

        }
    }
}