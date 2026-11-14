using SshServer.Interfaces.Storage;

namespace SshServer.Interfaces.Permissions;

/// <summary>The rules for the permissions and path filters of a user, used by the admin UI before it saves.</summary>
public static class PermissionRulesValidator
{
    /// <summary>The problems of the rules; empty when they are valid.</summary>
    public static IReadOnlyList<string> Validate(IReadOnlyDictionary<string, FilePermissions>? permissions, IReadOnlyDictionary<string, PathFilter>? filters)
    {
        var problems = new List<string>();

        var permissionPaths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var path in permissions?.Keys ?? Enumerable.Empty<string>())
        {
            if (ValidatePath(path) is { } problem)
                problems.Add(problem);
            else if (!permissionPaths.Add(VirtualPath.Normalize(path)))
                problems.Add($"The path {VirtualPath.Normalize(path)} has permissions twice.");
        }
        if (permissions is { Count: > 0 } && !permissionPaths.Contains(VirtualPath.Root))
            problems.Add("The permissions need an entry for \"/\".");

        var filterPaths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (path, filter) in filters ?? new Dictionary<string, PathFilter>())
        {
            if (ValidatePath(path) is { } problem)
                problems.Add(problem);
            else if (!filterPaths.Add(VirtualPath.Normalize(path)))
                problems.Add($"The path {VirtualPath.Normalize(path)} has a filter twice.");

            foreach (var pattern in filter.AllowedPatterns.Concat(filter.DeniedPatterns).Concat(filter.HiddenPatterns))
            {
                if (string.IsNullOrWhiteSpace(pattern))
                    problems.Add($"The filter of {path} has an empty pattern.");
                else if (pattern.IndexOfAny(['/', '\\']) >= 0)
                    problems.Add($"The pattern {pattern} cannot have '/' or '\\': a pattern matches a name, not a path.");
            }
        }

        return problems;
    }

    private static string? ValidatePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return "Enter a path for every row.";
        if (!path.StartsWith('/'))
            return $"The path {path} must start with \"/\".";
        if (path.Contains('\0'))
            return $"The path {path} is not valid.";
        return null;
    }
}
