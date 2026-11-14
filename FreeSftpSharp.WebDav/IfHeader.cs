namespace FreeSftpSharp.WebDav;

/// <summary>One condition of an If header list: a state token or an entity tag, maybe negated with "Not".</summary>
internal sealed record IfCondition(bool Not, string? StateToken, string? ETag);

/// <summary>One list of an If header: the conditions (all must be true) and the resource it is about (null: the request URL).</summary>
internal sealed record IfList(string? ResourceTag, IReadOnlyList<IfCondition> Conditions);

/// <summary>
/// The If request header of WebDAV (RFC 4918 section 10.4): lists of state tokens and entity tags, untagged (about the
/// request URL) or tagged with a resource URL. The header is true when one of its lists is true.
/// </summary>
internal sealed class IfHeader
{
    private IfHeader(IReadOnlyList<IfList> lists)
    {
        Lists = lists;
    }

    public IReadOnlyList<IfList> Lists { get; }

    /// <summary>Every state token of the header that is not negated: the lock tokens that the client submits.</summary>
    public IEnumerable<string> SubmittedTokens =>
        Lists.SelectMany(l => l.Conditions).Where(c => !c.Not && c.StateToken != null).Select(c => c.StateToken!);

    /// <summary>
    /// True when one list is true. <paramref name="resolve"/> gives, for a resource tag (null: the request URL), the
    /// entity tag of the resource (null when it does not exist) and the tokens of the locks that cover it; it returns
    /// null for a tag that is not a resource of this server, whose lists are false.
    /// </summary>
    public bool Evaluate(Func<string?, (string? ETag, IReadOnlyCollection<string> Tokens)?> resolve)
    {
        foreach (var list in Lists)
        {
            var state = resolve(list.ResourceTag);
            if (state is not { } resource)
                continue;
            if (list.Conditions.All(c => Matches(c, resource.ETag, resource.Tokens) != c.Not))
                return true;
        }
        return false;
    }

    private static bool Matches(IfCondition condition, string? etag, IReadOnlyCollection<string> tokens) =>
        condition.StateToken != null
            ? tokens.Contains(condition.StateToken)
            : etag != null && WeakEquals(condition.ETag!, etag);

    private static bool WeakEquals(string a, string b) => StripWeak(a) == StripWeak(b);

    private static string StripWeak(string tag) => tag.StartsWith("W/", StringComparison.Ordinal) ? tag[2..] : tag;

    /// <summary>Parses the header; null when it is absent. Throws <see cref="FormatException"/> for a malformed header.</summary>
    public static IfHeader? Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var lists = new List<IfList>();
        var i = 0;
        string? tag = null;
        bool? tagged = null;
        while (true)
        {
            SkipSpaces(value, ref i);
            if (i >= value.Length)
                break;
            if (value[i] == '<')
            {
                if (tagged == false)
                    throw new FormatException("An If header cannot mix tagged and untagged lists.");
                tagged = true;
                tag = ReadUntil(value, ref i, '<', '>');
                continue;
            }
            if (value[i] != '(')
                throw new FormatException("An If header list must start with '('.");
            if (tagged == null)
                tagged = false;
            if (tagged == true && tag == null)
                throw new FormatException("A tagged If header list needs a resource tag.");
            i++;
            var conditions = new List<IfCondition>();
            while (true)
            {
                SkipSpaces(value, ref i);
                if (i >= value.Length)
                    throw new FormatException("An If header list is not closed.");
                if (value[i] == ')')
                {
                    i++;
                    break;
                }
                var not = false;
                if (string.Compare(value, i, "Not", 0, 3, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    not = true;
                    i += 3;
                    SkipSpaces(value, ref i);
                }
                if (i < value.Length && value[i] == '<')
                    conditions.Add(new IfCondition(not, ReadUntil(value, ref i, '<', '>'), null));
                else if (i < value.Length && value[i] == '[')
                    conditions.Add(new IfCondition(not, null, ReadUntil(value, ref i, '[', ']')));
                else
                    throw new FormatException("An If header condition must be a state token or an entity tag.");
            }
            if (conditions.Count == 0)
                throw new FormatException("An If header list cannot be empty.");
            lists.Add(new IfList(tagged == true ? tag : null, conditions));
        }
        if (lists.Count == 0)
            throw new FormatException("The If header has no list.");
        return new IfHeader(lists);
    }

    private static void SkipSpaces(string value, ref int i)
    {
        while (i < value.Length && char.IsWhiteSpace(value[i]))
            i++;
    }

    private static string ReadUntil(string value, ref int i, char open, char close)
    {
        if (value[i] != open)
            throw new FormatException($"Expected '{open}' in the If header.");
        var end = value.IndexOf(close, i + 1);
        if (end < 0)
            throw new FormatException($"Expected '{close}' in the If header.");
        var result = value.Substring(i + 1, end - i - 1);
        i = end + 1;
        return result;
    }
}
