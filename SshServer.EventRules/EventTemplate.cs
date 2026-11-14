using System.Text;
using System.Text.RegularExpressions;

namespace SshServer.EventRules;

/// <summary>
/// The placeholders of the action options: <c>{{Name}}</c> is replaced by the value <c>Name</c> of the run
/// (<see cref="EventPlaceholders"/>), <c>{{Name | urlencode}}</c> by the value with a filter. An unknown name is replaced
/// by an empty text. Filters: <c>urlencode</c>, <c>lower</c>, <c>upper</c>. The result is plain text: the actions never
/// give it to a shell.
/// </summary>
public static partial class EventTemplate
{
    public static IReadOnlyList<string> Filters { get; } = ["urlencode", "lower", "upper"];

    [GeneratedRegex(@"\{\{\s*([A-Za-z][A-Za-z0-9_]*)\s*(?:\|\s*([A-Za-z0-9_]+)\s*)?\}\}", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 500)]
    private static partial Regex Placeholder();

    public static string Render(string? template, IReadOnlyDictionary<string, string> values)
    {
        if (string.IsNullOrEmpty(template) || !template.Contains("{{", StringComparison.Ordinal))
            return template ?? string.Empty;
        return Placeholder().Replace(template, match =>
        {
            var value = values.TryGetValue(match.Groups[1].Value, out var v) ? v : string.Empty;
            return match.Groups[2].Success ? Apply(match.Groups[2].Value, value) : value;
        });
    }

    /// <summary>The errors of a template: unknown filters and placeholders that are not closed.</summary>
    public static IReadOnlyList<string> Validate(string? template)
    {
        if (string.IsNullOrEmpty(template))
            return [];
        var errors = new List<string>();
        foreach (Match match in Placeholder().Matches(template))
        {
            if (match.Groups[2].Success && !Filters.Contains(match.Groups[2].Value.ToLowerInvariant()))
                errors.Add($"The filter '{match.Groups[2].Value}' is not known; use {string.Join(", ", Filters)}.");
        }
        if (Placeholder().Replace(template, string.Empty).Contains("{{", StringComparison.Ordinal))
            errors.Add("A placeholder is not valid; write it as {{Name}} or {{Name | urlencode}}.");
        return errors;
    }

    private static string Apply(string filter, string value) => filter.ToLowerInvariant() switch
    {
        "urlencode" => Uri.EscapeDataString(value),
        "lower" => value.ToLowerInvariant(),
        "upper" => value.ToUpperInvariant(),
        _ => value,
    };
}

/// <summary>A pattern of names: <c>*</c> is any text, <c>?</c> one character; the whole name must match, case-insensitively.</summary>
public sealed class NamePattern
{
    private readonly Regex _regex;

    public NamePattern(string pattern)
    {
        Pattern = pattern;
        var builder = new StringBuilder("^");
        foreach (var c in pattern)
            builder.Append(c switch { '*' => ".*", '?' => ".", _ => Regex.Escape(c.ToString()) });
        builder.Append('$');
        _regex = new Regex(builder.ToString(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline,
            TimeSpan.FromMilliseconds(100));
    }

    public string Pattern { get; }

    public bool IsMatch(string? name) => name != null && _regex.IsMatch(name);
}
