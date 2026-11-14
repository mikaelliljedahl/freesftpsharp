using SshServer.Interfaces.Permissions;

namespace FxSshSftpServer.WebClient
{
    /// <summary>What the browser may offer for the entries of one directory.</summary>
    public sealed record DirectoryActions(bool List, bool Download, bool Upload, bool Overwrite, bool Delete, bool Rename, bool CreateDirectory)
    {
        /// <summary>True when the directory has at least one action that changes it.</summary>
        public bool AnyChange => Upload || Overwrite || Delete || Rename || CreateDirectory;
    }

    /// <summary>
    /// Maps the effective permissions of a user (#59) to the controls of the web client, with the same path rules as the
    /// permission decorator (<see cref="PathRuleResolver"/>). It only decides which buttons the page shows: every request
    /// still goes through <c>PermissionFileSystem</c>, which refuses what the user may not do.
    /// </summary>
    public sealed class ClientPermissionMap
    {
        private readonly PathRuleResolver _rules;

        public ClientPermissionMap(EffectivePermissions permissions, bool caseInsensitivePaths)
        {
            _rules = new PathRuleResolver(permissions, caseInsensitivePaths);
        }

        /// <summary>The actions on the entries in <paramref name="directory"/> (a virtual path).</summary>
        public DirectoryActions For(string directory)
        {
            var granted = _rules.PermissionsOf(directory);
            bool Has(FilePermissions p) => (granted & p) != 0;
            return new DirectoryActions(
                List: Has(FilePermissions.List),
                Download: Has(FilePermissions.Download),
                Upload: Has(FilePermissions.Upload),
                Overwrite: Has(FilePermissions.Overwrite),
                Delete: Has(FilePermissions.Delete),
                Rename: Has(FilePermissions.Rename),
                CreateDirectory: Has(FilePermissions.CreateDirectories));
        }

        /// <summary>True when the name of the file at <paramref name="path"/> passes the path filters of its directory.</summary>
        public bool IsFileNameAllowed(string path) => _rules.IsFileNameAllowed(path);
    }
}
