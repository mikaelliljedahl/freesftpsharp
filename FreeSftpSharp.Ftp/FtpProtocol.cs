using System.Globalization;
using System.Text;

namespace FreeSftpSharp.Ftp;

/// <summary>One command line of the client: the verb (upper case) and the argument as sent (RFC 959 section 5.3).</summary>
internal readonly record struct FtpCommand(string Verb, string Argument)
{
    /// <summary>
    /// Parses a line without its CRLF. The verb is 3 or 4 ASCII letters; the argument is everything after the first
    /// space, spaces included (file names may have them). Null when the line has no valid verb.
    /// </summary>
    public static FtpCommand? Parse(string line)
    {
        var space = line.IndexOf(' ');
        var verb = space < 0 ? line : line[..space];
        if (verb.Length is < 3 or > 4 || !verb.All(char.IsAsciiLetter))
            return null;
        return new FtpCommand(verb.ToUpperInvariant(), space < 0 ? "" : line[(space + 1)..]);
    }

    /// <summary>The command for the log: the argument of PASS is never shown.</summary>
    public override string ToString() => Verb == "PASS" ? "PASS ****" : Argument.Length == 0 ? Verb : Verb + " " + Argument;
}

/// <summary>The replies of the server (RFC 959 section 4.2).</summary>
internal static class FtpReply
{
    /// <summary>
    /// "code text" CRLF; a text with several lines becomes a multi-line reply ("code-first", the middle lines with a
    /// leading space, "code last"). CR and LF in the text never end a reply early.
    /// </summary>
    public static string Format(int code, string text)
    {
        var lines = text.Replace("\r", "", StringComparison.Ordinal).Split('\n');
        var codeText = code.ToString(CultureInfo.InvariantCulture);
        if (lines.Length == 1)
            return codeText + " " + lines[0] + "\r\n";
        var builder = new StringBuilder();
        builder.Append(codeText).Append('-').Append(lines[0]).Append("\r\n");
        for (var i = 1; i < lines.Length - 1; i++)
            builder.Append(' ').Append(lines[i]).Append("\r\n");
        builder.Append(codeText).Append(' ').Append(lines[^1]).Append("\r\n");
        return builder.ToString();
    }

    /// <summary>A path in a 257 reply: in double quotes, a quote in the path doubled (RFC 959 appendix II).</summary>
    public static string QuotePath(string path) => "\"" + path.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
}
