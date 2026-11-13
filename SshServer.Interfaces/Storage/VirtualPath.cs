namespace SshServer.Interfaces.Storage;

/// <summary>
/// Virtual paths of an <see cref="IFileSystem"/>: "/" separated, "/" is the user root. Every backend normalizes the
/// paths it receives with <see cref="Normalize"/>, so a path can never leave the user root.
/// </summary>
public static class VirtualPath
{
    /// <summary>The user root.</summary>
    public const string Root = "/";

    /// <summary>
    /// Converts a path from a client to a normalized virtual path that starts with "/".
    /// Both "/" and "\" are separators. "." segments are removed. A ".." segment removes
    /// the previous segment, and a ".." segment at the root stays at the root.
    /// </summary>
    public static string Normalize(string? path)
    {
        var segments = new List<string>();
        foreach (var segment in (path ?? string.Empty).Split('/', '\\'))
        {
            if (segment.Length == 0 || segment == ".")
                continue;

            if (segment == "..")
            {
                if (segments.Count > 0)
                    segments.RemoveAt(segments.Count - 1);
                continue;
            }

            segments.Add(segment);
        }

        return "/" + string.Join('/', segments);
    }

    /// <summary>The path of the entry <paramref name="name"/> in the normalized directory <paramref name="directory"/>.</summary>
    public static string Combine(string directory, string name)
        => directory == Root ? Root + name : directory + "/" + name;

    /// <summary>The last segment of a normalized path; "/" for the root.</summary>
    public static string GetName(string normalizedPath)
        => normalizedPath == Root ? Root : normalizedPath.Substring(normalizedPath.LastIndexOf('/') + 1);

    /// <summary>The parent directory of a normalized path; the root for the root.</summary>
    public static string GetParent(string normalizedPath)
    {
        var index = normalizedPath.LastIndexOf('/');
        return index <= 0 ? Root : normalizedPath.Substring(0, index);
    }
}
