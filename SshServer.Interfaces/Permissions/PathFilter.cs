namespace SshServer.Interfaces.Permissions;

/// <summary>
/// File name rules of a virtual directory (<see cref="User.PathFilters"/>). Like <see cref="FilePermissions"/>, a filter
/// applies to the directory and every directory below it, until a more specific path has its own filter.
/// <para>
/// The patterns match the name of an entry, not its path. They use <c>*</c> (any characters) and <c>?</c> (one
/// character) and ignore case, so <c>*.exe</c> also matches <c>SETUP.EXE</c>.
/// </para>
/// </summary>
public sealed class PathFilter
{
    /// <summary>When not empty, only files whose name matches one of these patterns can be opened, renamed to or deleted.</summary>
    public List<string> AllowedPatterns { get; set; } = new();

    /// <summary>Files whose name matches one of these patterns cannot be opened, renamed to or deleted. They are still listed.</summary>
    public List<string> DeniedPatterns { get; set; } = new();

    /// <summary>
    /// Files and directories whose name matches one of these patterns do not exist for the user: they are not listed,
    /// and every operation on them, or on a path below them, fails with "no such file".
    /// </summary>
    public List<string> HiddenPatterns { get; set; } = new();

    /// <summary>True when the filter has no pattern.</summary>
    public bool IsEmpty => AllowedPatterns.Count == 0 && DeniedPatterns.Count == 0 && HiddenPatterns.Count == 0;
}
