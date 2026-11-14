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

    /// <summary>The table rows of permissions and path filters and their checks, for the user and the group forms.</summary>
    public static class PermissionTables
    {
        /// <summary>The rows of the stored permissions: "/" first (All when it is not stored), then by path.</summary>
        public static List<PermissionRow> RowsOf(Dictionary<string, FilePermissions> permissions)
        {
            var rows = (permissions ?? new Dictionary<string, FilePermissions>())
                .Select(p => new PermissionRow { Path = p.Key, Permissions = p.Value })
                .ToList();
            if (!rows.Any(r => r.IsRoot))
                rows.Add(PermissionRow.Root());
            return rows.OrderBy(r => r.IsRoot ? 0 : 1).ThenBy(r => r.Path, StringComparer.Ordinal).ToList();
        }

        public static List<PathFilterRow> FilterRowsOf(Dictionary<string, PathFilter> filters) =>
            (filters ?? new Dictionary<string, PathFilter>())
                .OrderBy(f => f.Key, StringComparer.Ordinal)
                .Select(f => PathFilterRow.From(f.Key, f.Value))
                .ToList();

        public static Dictionary<string, FilePermissions> ToDictionary(IEnumerable<PermissionRow> rows)
        {
            var result = new Dictionary<string, FilePermissions>(StringComparer.Ordinal);
            foreach (var row in rows)
                result.TryAdd(NormalizedOrRaw(row.Path), row.Permissions);
            return result;
        }

        public static Dictionary<string, PathFilter> ToDictionary(IEnumerable<PathFilterRow> rows)
        {
            var result = new Dictionary<string, PathFilter>(StringComparer.Ordinal);
            foreach (var row in rows)
                result.TryAdd(NormalizedOrRaw(row.Path), row.ToFilter());
            return result;
        }

        /// <summary>The filters without the empty ones; null when none is left (not set).</summary>
        public static Dictionary<string, PathFilter> NonEmptyFilters(IEnumerable<PathFilterRow> rows)
        {
            var filters = ToDictionary(rows).Where(f => !f.Value.IsEmpty).ToDictionary(f => f.Key, f => f.Value, StringComparer.Ordinal);
            return filters.Count == 0 ? null : filters;
        }

        /// <summary>True for the rows of a new user: "/" with every permission and nothing else, the same as no permissions.</summary>
        public static bool IsRootAllOnly(IReadOnlyCollection<PermissionRow> rows) =>
            rows.Count == 1 && rows.First().IsRoot && rows.First().Permissions == FilePermissions.All;

        /// <summary>A valid path is stored normalized; an invalid one is kept as typed, so the validation can tell about it.</summary>
        public static string NormalizedOrRaw(string path)
        {
            var trimmed = (path ?? "").Trim();
            return trimmed.StartsWith('/') ? VirtualPath.Normalize(trimmed) : trimmed;
        }

        /// <summary>The problems of the permission rows (first) and the filter rows (second).</summary>
        public static (IReadOnlyList<string> Permissions, IReadOnlyList<string> Filters) Problems(
            IReadOnlyCollection<PermissionRow> permissions, IReadOnlyCollection<PathFilterRow> filters)
        {
            var permissionProblems = new List<string>();
            var filterProblems = new List<string>();
            // Rows that are typed twice are found here; the dictionaries keep only the first of them.
            foreach (var path in permissions.GroupBy(r => NormalizedOrRaw(r.Path), StringComparer.Ordinal).Where(g => g.Count() > 1 && g.Key.Length > 0))
                permissionProblems.Add($"The path {path.Key} has permissions twice.");
            foreach (var path in filters.GroupBy(r => NormalizedOrRaw(r.Path), StringComparer.Ordinal).Where(g => g.Count() > 1 && g.Key.Length > 0))
                filterProblems.Add($"The path {path.Key} has a filter twice.");
            permissionProblems.AddRange(PermissionRulesValidator.Validate(ToDictionary(permissions), null));
            filterProblems.AddRange(PermissionRulesValidator.Validate(null, ToDictionary(filters)));
            return (permissionProblems, filterProblems);
        }
    }
}
