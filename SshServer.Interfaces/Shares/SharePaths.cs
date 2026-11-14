using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;

namespace SshServer.Interfaces.Shares;

/// <summary>
/// The containment check of a share (#70): a request of the share may use only the shared paths and what is below them.
/// The paths are compared like the storage and the permission rules compare them (<see cref="PathRuleResolver.Canonical"/>),
/// so another spelling of a directory on a case-insensitive storage is the same directory, and ".." never leaves a shared
/// folder (the path is normalized first).
/// </summary>
public static class SharePaths
{
    /// <summary>True when <paramref name="path"/> is one of <paramref name="roots"/> or below one of them.</summary>
    public static bool Contains(IEnumerable<string> roots, string? path, bool caseInsensitivePaths)
    {
        if (path == null)
            return false;
        var canonical = PathRuleResolver.Canonical(path, caseInsensitivePaths);
        foreach (var root in roots)
        {
            var canonicalRoot = PathRuleResolver.Canonical(root, caseInsensitivePaths);
            // A share of the root would share everything: never contained (the creation refuses it too).
            if (canonicalRoot != VirtualPath.Root && PathRuleResolver.IsAtOrBelow(canonical, canonicalRoot))
                return true;
        }
        return false;
    }

    /// <summary>The shared path that holds <paramref name="path"/>, or null (see <see cref="Contains"/>).</summary>
    public static string? RootOf(IEnumerable<string> roots, string? path, bool caseInsensitivePaths) =>
        path == null ? null : roots.FirstOrDefault(root => Contains([root], path, caseInsensitivePaths));

    /// <summary>
    /// The paths of a new share, normalized and without duplicates; the errors for the user are added to
    /// <paramref name="errors"/> (no path, the root, too many).
    /// </summary>
    public static List<string> Normalize(IEnumerable<string?>? paths, ICollection<string> errors)
    {
        var result = new List<string>();
        foreach (var raw in paths ?? [])
        {
            if (string.IsNullOrWhiteSpace(raw))
                continue;
            var path = VirtualPath.Normalize(raw.Trim());
            if (path == VirtualPath.Root)
            {
                errors.Add("Share files or folders, not the whole home folder.");
                continue;
            }
            if (!result.Contains(path, StringComparer.Ordinal))
                result.Add(path);
        }
        if (result.Count == 0 && errors.Count == 0)
            errors.Add("Select at least one file or folder.");
        if (result.Count > ShareRules.MaxPaths)
            errors.Add($"A share can have at most {ShareRules.MaxPaths} paths.");
        return result;
    }
}
