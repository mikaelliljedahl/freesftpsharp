using System.Text;
using System.Text.RegularExpressions;

namespace SshServer.Interfaces.Storage;

/// <summary>
/// A glob over virtual paths: <c>*</c> is any text within one directory, <c>**</c> any text over directories, <c>?</c>
/// one character except <c>/</c>. The whole path must match, case-sensitively. Example: <c>/incoming/**/*.csv</c>.
/// </summary>
public sealed class PathGlob
{
    private readonly Regex _regex;

    private PathGlob(string pattern, Regex regex)
    {
        Pattern = pattern;
        _regex = regex;
    }

    public string Pattern { get; }

    public static PathGlob Parse(string pattern)
    {
        var builder = new StringBuilder("^");
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == '*')
            {
                if (i + 1 < pattern.Length && pattern[i + 1] == '*')
                {
                    i++;
                    // "/**/" also matches "/" (no directory between).
                    if (i + 1 < pattern.Length && pattern[i + 1] == '/')
                    {
                        i++;
                        builder.Append("(?:.*/)?");
                    }
                    else
                    {
                        builder.Append(".*");
                    }
                }
                else
                {
                    builder.Append("[^/]*");
                }
            }
            else if (c == '?')
            {
                builder.Append("[^/]");
            }
            else
            {
                builder.Append(Regex.Escape(c.ToString()));
            }
        }
        builder.Append('$');
        return new PathGlob(pattern, new Regex(builder.ToString(), RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)));
    }

    public bool IsMatch(string path) => _regex.IsMatch(path);
}
