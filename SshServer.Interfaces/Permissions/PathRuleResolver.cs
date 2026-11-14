using System.IO.Enumeration;
using SshServer.Interfaces.Storage;

namespace SshServer.Interfaces.Permissions;

/// <summary>
/// Finds the rules of <see cref="EffectivePermissions"/> for a virtual path: the entry with the longest matching
/// directory wins, so the rules of "/incoming" apply to "/incoming/2026/a.txt" until "/incoming/2026" has its own.
/// <para>
/// The paths are compared like the storage compares them. On a storage with
/// <see cref="StorageCapabilities.CaseInsensitivePaths"/> the case is ignored and trailing dots and spaces of a segment
/// are removed (the Windows rules), so "/INCOMING./a.txt" gets the rules of "/incoming", because it is the same
/// directory on the disk. File name patterns always ignore case.
/// </para>
/// </summary>
public sealed class PathRuleResolver
{
    private readonly bool _caseInsensitivePaths;
    private readonly (string Key, FilePermissions Value)[] _permissions;
    private readonly (string Key, PathFilter Filter)[] _filters;

    public PathRuleResolver(EffectivePermissions rules, bool caseInsensitivePaths)
    {
        _caseInsensitivePaths = caseInsensitivePaths;
        // Longest key first: the first match is the most specific one.
        _permissions = rules.Permissions
            .Select(p => (Key: Canonical(p.Key), p.Value))
            .OrderByDescending(p => p.Key.Length)
            .ToArray();
        _filters = rules.Filters
            .Select(f => (Key: Canonical(f.Key), Filter: f.Value))
            .OrderByDescending(f => f.Key.Length)
            .ToArray();
    }

    /// <summary>The permissions in <paramref name="directory"/> (a virtual path).</summary>
    public FilePermissions PermissionsOf(string directory)
    {
        var canonical = Canonical(directory);
        foreach (var (key, value) in _permissions)
        {
            if (IsAtOrBelow(canonical, key))
                return value;
        }
        return FilePermissions.All; // not reached: EffectivePermissions always has "/"
    }

    /// <summary>The path filter in <paramref name="directory"/> (a virtual path), or null when none applies.</summary>
    public PathFilter? FilterOf(string directory) => FilterOfCanonical(Canonical(directory));

    /// <summary>True when <paramref name="path"/>, or a directory on the way to it, matches a hidden pattern.</summary>
    public bool IsHidden(string path)
    {
        if (_filters.Length == 0)
            return false;
        var directory = VirtualPath.Root;
        foreach (var segment in Segments(Canonical(path)))
        {
            if (FilterOfCanonical(directory) is { } filter && filter.HiddenPatterns.Any(p => Matches(p, segment)))
                return true;
            directory = VirtualPath.Combine(directory, segment);
        }
        return false;
    }

    /// <summary>
    /// True when the name of the file <paramref name="path"/> passes the allowed and denied patterns of its directory.
    /// </summary>
    public bool IsFileNameAllowed(string path)
    {
        var canonical = Canonical(path);
        if (canonical == VirtualPath.Root || FilterOfCanonical(VirtualPath.GetParent(canonical)) is not { } filter)
            return true;
        var name = VirtualPath.GetName(canonical);
        if (filter.DeniedPatterns.Any(p => Matches(p, name)))
            return false;
        return filter.AllowedPatterns.Count == 0 || filter.AllowedPatterns.Any(p => Matches(p, name));
    }

    /// <summary>True when a permission or filter entry exists for <paramref name="path"/> or for a path below it.</summary>
    public bool HasRulesAtOrBelow(string path)
    {
        var canonical = Canonical(path);
        return _permissions.Any(p => IsAtOrBelow(p.Key, canonical)) || _filters.Any(f => IsAtOrBelow(f.Key, canonical));
    }

    private PathFilter? FilterOfCanonical(string canonicalDirectory)
    {
        foreach (var (key, filter) in _filters)
        {
            if (IsAtOrBelow(canonicalDirectory, key))
                return filter;
        }
        return null;
    }

    private static bool Matches(string pattern, string name) =>
        FileSystemName.MatchesSimpleExpression(pattern, name, ignoreCase: true);

    /// <summary>True when <paramref name="path"/> is <paramref name="directory"/> or below it (both canonical).</summary>
    private static bool IsAtOrBelow(string path, string directory) =>
        directory == VirtualPath.Root
        || path == directory
        || (path.Length > directory.Length && path[directory.Length] == '/' && path.StartsWith(directory, StringComparison.Ordinal));

    private static IEnumerable<string> Segments(string canonicalPath) =>
        canonicalPath.Split('/', StringSplitOptions.RemoveEmptyEntries);

    /// <summary>The normalized path, in the form in which the storage compares it.</summary>
    private string Canonical(string path)
    {
        var normalized = VirtualPath.Normalize(path);
        if (!_caseInsensitivePaths)
            return normalized;
        var segments = Segments(normalized)
            .Select(s => s.TrimEnd('.', ' ').ToUpperInvariant())
            .Where(s => s.Length > 0);
        return VirtualPath.Root + string.Join('/', segments);
    }
}
