using System;
using System.Text;
using LiteDB;
using SshServerLoader.Settings;

namespace FxSsh.SshServerLoader
{
    public class SettingsRepository : IDisposable
    {
        public void Dispose()
        {
            if (db != null)
                db.Dispose();
        }

        private LiteDatabase db;
        public ServerSettings ServerSettings { get; set; }
        public User GetUser(string Username)
        {
            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<User>("users");

            return usercol.FindOne(x => x.Username == Username);

        }
        public SettingsRepository()
        {
            db = new LiteDatabase("config.db");

            var serversettings = db.GetCollection<ServerSettings>("settings");

            // Get a collection (or create, if doesn't exist)
            var usercol = db.GetCollection<User>("users");

            // Index users using username property
            usercol.EnsureIndex(x => x.Username);

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