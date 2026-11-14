using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using LiteDB;
using SshServer.Interfaces;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;


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

        /// <summary>
        /// The last login in files of versions before issue #61 (the field "LastSuccessfulLogin"). The repository moves it
        /// to <see cref="User.LastLoginAt"/> at start.
        /// </summary>
        [BsonField("LastSuccessfulLogin")]
        public DateTime? LegacyLastLogin { get; set; }

        /// <summary>True for permissions that are only "/" = All: the same as no permissions of the user (issue #61).</summary>
        public static bool IsRootAllOnly(Dictionary<string, FilePermissions>? permissions) =>
            permissions is { Count: 1 } && permissions.TryGetValue("/", out var root) && root == FilePermissions.All;

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
            this.LastLoginAt = user.LastLoginAt;
            this.OnlyWhitelistedIps = user.OnlyWhitelistedIps;
            this.PublicKeys = user.PublicKeys;
            this.AllowedAuthMethods = user.AllowedAuthMethods;
            this.RequireAllOf = user.RequireAllOf;
            this.UserRootDirectory = user.UserRootDirectory;
            this.WhitelistedIps = user.WhitelistedIps;
            this.Permissions = user.Permissions;
            this.PathFilters = user.PathFilters;
            this.Storage = user.Storage;
            this.DiskQuota = user.DiskQuota;
            this.TransferQuota = user.TransferQuota;
            this.Bandwidth = user.Bandwidth;
            this.VirtualFolders = (user.VirtualFolders ?? new List<VirtualFolderMount>()).ToList();
            CopyLifecycle(user, this);
            this.RoleId = user.RoleId;
            this.Id = new ObjectId();
        }

        public UserWithObjectId()
        {
        }

        /// <summary>The fields of issue #61.</summary>
        internal static void CopyLifecycle(User from, User to)
        {
            to.Description = from.Description;
            to.Status = from.Status;
            to.ExpiresAt = from.ExpiresAt;
            to.MaxSessions = from.MaxSessions;
            to.PasswordChangedAt = from.PasswordChangedAt;
            to.PrimaryGroupId = from.PrimaryGroupId;
            to.SecondaryGroupIds = (from.SecondaryGroupIds ?? new List<int>()).ToList();
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
            _serverSettings.PasswordMaxAgeDays = UpdatedSettings.PasswordMaxAgeDays;
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
            user.LastLoginAt = UpdatedUser.LastLoginAt;
            user.OnlyWhitelistedIps = UpdatedUser.OnlyWhitelistedIps;
            user.PublicKeys = UpdatedUser.PublicKeys;
            user.AllowedAuthMethods = UpdatedUser.AllowedAuthMethods;
            user.RequireAllOf = UpdatedUser.RequireAllOf;
            user.UserRootDirectory = UpdatedUser.UserRootDirectory;
            user.WhitelistedIps = UpdatedUser.WhitelistedIps;
            user.Permissions = UpdatedUser.Permissions;
            user.PathFilters = UpdatedUser.PathFilters;
            user.Storage = UpdatedUser.Storage;
            user.DiskQuota = UpdatedUser.DiskQuota;
            user.TransferQuota = UpdatedUser.TransferQuota;
            user.Bandwidth = UpdatedUser.Bandwidth;
            user.VirtualFolders = (UpdatedUser.VirtualFolders ?? new List<VirtualFolderMount>()).ToList();
            UserWithObjectId.CopyLifecycle(UpdatedUser, user);
            user.RoleId = UpdatedUser.RoleId;
            return usercol.Update(user);
            
        }

        private ILiteCollection<VirtualFolder> Folders => db.GetCollection<VirtualFolder>("virtualfolders");

        public List<VirtualFolder> GetVirtualFolders() => Folders.FindAll().OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase).ToList();

        public VirtualFolder? GetVirtualFolder(int id) => Folders.FindById(id);

        public bool AddVirtualFolder(VirtualFolder folder)
        {
            if (string.IsNullOrWhiteSpace(folder.Name) || GetVirtualFolders().Any(f => string.Equals(f.Name, folder.Name, StringComparison.OrdinalIgnoreCase)))
                return false;
            var stored = new VirtualFolder { Name = folder.Name, Description = folder.Description, Storage = folder.Storage };
            Folders.Insert(stored);
            folder.Id = stored.Id;
            return true;
        }

        public bool UpdateVirtualFolder(VirtualFolder folder)
        {
            if (string.IsNullOrWhiteSpace(folder.Name) || Folders.FindById(folder.Id) == null
                || GetVirtualFolders().Any(f => f.Id != folder.Id && string.Equals(f.Name, folder.Name, StringComparison.OrdinalIgnoreCase)))
                return false;
            return Folders.Update(new VirtualFolder { Id = folder.Id, Name = folder.Name, Description = folder.Description, Storage = folder.Storage });
        }

        public bool RemoveVirtualFolder(int id)
        {
            if (!Folders.Delete(id))
                return false;
            var usercol = db.GetCollection<UserWithObjectId>("users");
            foreach (var user in usercol.FindAll().Where(u => u.VirtualFolders != null && u.VirtualFolders.Any(m => m.VirtualFolderId == id)).ToList())
            {
                user.VirtualFolders.RemoveAll(m => m.VirtualFolderId == id);
                usercol.Update(user);
            }
            foreach (var group in GroupCollection.FindAll().Where(g => g.VirtualFolders != null && g.VirtualFolders.Any(m => m.VirtualFolderId == id)).ToList())
            {
                group.VirtualFolders.RemoveAll(m => m.VirtualFolderId == id);
                GroupCollection.Update(group);
            }
            return true;
        }

        private ILiteCollection<Group> GroupCollection => db.GetCollection<Group>("groups");

        public List<Group> GetGroups() => GroupCollection.FindAll().OrderBy(g => g.Name, StringComparer.OrdinalIgnoreCase).ToList();

        public Group? GetGroup(int id) => GroupCollection.FindById(id);

        public bool AddGroup(Group group)
        {
            if (string.IsNullOrWhiteSpace(group.Name) || GetGroups().Any(g => string.Equals(g.Name, group.Name, StringComparison.OrdinalIgnoreCase)))
                return false;
            var stored = group.Clone();
            stored.Id = 0;
            GroupCollection.Insert(stored);
            group.Id = stored.Id;
            return true;
        }

        public bool UpdateGroup(Group group)
        {
            if (string.IsNullOrWhiteSpace(group.Name) || GroupCollection.FindById(group.Id) == null
                || GetGroups().Any(g => g.Id != group.Id && string.Equals(g.Name, group.Name, StringComparison.OrdinalIgnoreCase)))
                return false;
            return GroupCollection.Update(group.Clone());
        }

        public bool RemoveGroup(int id)
        {
            var usercol = db.GetCollection<UserWithObjectId>("users");
            if (usercol.FindAll().Any(u => GroupService.IsMember(u, id)))
                return false;
            return GroupCollection.Delete(id);
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

            // Issue #61: the last login has a new field, "/" = All is the same as no permissions (so a group can give
            // them), and the age of a password counts from the upgrade.
            foreach (var old in usercol.FindAll().Where(u => u.LegacyLastLogin != null || UserWithObjectId.IsRootAllOnly(u.Permissions)
                                                             || (u.PasswordChangedAt == null && !string.IsNullOrEmpty(u.HashedPassword))).ToList())
            {
                if (old.LegacyLastLogin is { } last && old.LastLoginAt == null && last != default)
                    old.LastLoginAt = last;
                old.LegacyLastLogin = null;
                if (UserWithObjectId.IsRootAllOnly(old.Permissions))
                    old.Permissions = null;
                if (old.PasswordChangedAt == null && !string.IsNullOrEmpty(old.HashedPassword))
                    old.PasswordChangedAt = DateTime.UtcNow;
                usercol.Update(old);
            }

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