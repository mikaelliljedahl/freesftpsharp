using SshServer.Api.Endpoints;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Quotas;
using SshServer.Interfaces.Storage;

namespace SshServer.Api;

/// <summary>The permissions and path filters of a user or a group in the API: names to flags, and paths normalized.</summary>
internal static class PermissionModels
{
    /// <summary>The permissions by normalized path, or null when none are given (not set).</summary>
    public static Dictionary<string, FilePermissions>? Parse(Dictionary<string, List<string>>? permissions, ValidationErrors errors)
    {
        if (permissions is not { Count: > 0 })
            return null;
        var result = new Dictionary<string, FilePermissions>(StringComparer.Ordinal);
        foreach (var (path, names) in permissions)
        {
            var unknown = new List<string>();
            var flags = FlagNames.Parse<FilePermissions>(names, unknown);
            errors.AddRange("permissions", unknown.Select(n => $"'{n}' is not a file permission."));
            if (!result.TryAdd(NormalizedOrRaw(path), flags))
                errors.Add("permissions", $"The path {NormalizedOrRaw(path)} has permissions twice.");
        }
        return result;
    }

    /// <summary>The filters that are not empty by normalized path, or null when there is none.</summary>
    public static Dictionary<string, PathFilter>? ParseFilters(Dictionary<string, PathFilterModel>? filters)
    {
        var result = (filters ?? [])
            .Select(f => (Path: NormalizedOrRaw(f.Key), Filter: f.Value?.ToFilter() ?? new PathFilter()))
            .Where(f => !f.Filter.IsEmpty)
            .GroupBy(f => f.Path, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().Filter, StringComparer.Ordinal);
        return result.Count == 0 ? null : result;
    }

    public static Dictionary<string, List<string>>? Names(Dictionary<string, FilePermissions>? permissions) =>
        UserAttributes.PermissionNames(permissions);

    public static Dictionary<string, PathFilterModel>? Models(Dictionary<string, PathFilter>? filters) =>
        filters is { Count: > 0 } ? filters.ToDictionary(p => p.Key, p => PathFilterModel.From(p.Value), StringComparer.Ordinal) : null;

    public static List<VirtualFolderMount> Mounts(IEnumerable<VirtualFolderMountModel>? mounts) => (mounts ?? [])
        .Select(m => new VirtualFolderMount { VirtualFolderId = m.VirtualFolderId, MountPath = NormalizedOrRaw(m.MountPath), Quota = DiskQuota.OrNull(m.Quota) })
        .ToList();

    /// <summary>A valid path is stored normalized; an invalid one is kept as given, so the validation tells about it.</summary>
    public static string NormalizedOrRaw(string? path)
    {
        var trimmed = (path ?? "").Trim();
        return trimmed.StartsWith('/') ? VirtualPath.Normalize(trimmed) : trimmed;
    }
}
