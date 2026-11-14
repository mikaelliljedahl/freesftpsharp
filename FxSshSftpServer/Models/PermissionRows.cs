using System;
using System.Collections.Generic;
using System.Linq;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;

namespace FxSshSftpServer.Models
{
    /// <summary>One row of the permission table on the users page: a virtual directory and its permissions.</summary>
    public sealed class PermissionRow
    {
        /// <summary>The permissions in the order of the table columns, with their column titles.</summary>
        public static readonly IReadOnlyList<(FilePermissions Flag, string Title, string Description)> Columns =
        [
            (FilePermissions.List, "List", "List the directory"),
            (FilePermissions.Download, "Download", "Read files"),
            (FilePermissions.Upload, "Upload", "Create new files"),
            (FilePermissions.Overwrite, "Overwrite", "Write to existing files"),
            (FilePermissions.Delete, "Delete", "Remove files and directories"),
            (FilePermissions.Rename, "Rename", "Rename and move"),
            (FilePermissions.CreateDirectories, "Mkdir", "Create directories"),
            (FilePermissions.CreateSymlinks, "Symlink", "Create symbolic links"),
            (FilePermissions.ChangeMode, "Chmod", "Change the permission bits"),
            (FilePermissions.ChangeTimes, "Times", "Change the file times"),
        ];

        public string Path { get; set; } = "";

        public FilePermissions Permissions { get; set; }

        /// <summary>The "/" row is always there; its path cannot change and it cannot be removed.</summary>
        public bool IsRoot => VirtualPath.Normalize(Path) == VirtualPath.Root && Path.Trim().StartsWith('/');

        public bool Has(FilePermissions flag) => (Permissions & flag) == flag;

        public void Set(FilePermissions flag, bool value) =>
            Permissions = value ? Permissions | flag : Permissions & ~flag;

        public static PermissionRow Root() => new() { Path = VirtualPath.Root, Permissions = FilePermissions.All };
    }

    /// <summary>One row of the path filter table: a virtual directory and its patterns, separated by commas or spaces.</summary>
    public sealed class PathFilterRow
    {
        public string Path { get; set; } = "";
        public string Allowed { get; set; } = "";
        public string Denied { get; set; } = "";
        public string Hidden { get; set; } = "";

        public PathFilter ToFilter() => new()
        {
            AllowedPatterns = Patterns(Allowed),
            DeniedPatterns = Patterns(Denied),
            HiddenPatterns = Patterns(Hidden),
        };

        public static PathFilterRow From(string path, PathFilter filter) => new()
        {
            Path = path,
            Allowed = string.Join(", ", filter.AllowedPatterns),
            Denied = string.Join(", ", filter.DeniedPatterns),
            Hidden = string.Join(", ", filter.HiddenPatterns),
        };

        private static List<string> Patterns(string text) =>
            (text ?? "").Split([',', ' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).ToList();
    }
}
