using System.Globalization;
using System.Text;

namespace SshServer.Interfaces.Audit;

/// <summary>Writes audit entries as CSV (RFC 4180, UTF-8, comma separated), for the export of the admin UI and the API.</summary>
public static class AuditCsv
{
    private static readonly string[] Header =
    [
        "Timestamp (UTC)", "Category", "Type", "Status", "Username", "Remote IP", "Protocol", "Path", "Target path",
        "Size", "Elapsed (ms)", "Actor", "Session", "Message", "Details",
    ];

    public static string Write(IEnumerable<AuditEntry> entries)
    {
        var csv = new StringBuilder();
        AppendRow(csv, Header);
        foreach (var e in entries)
        {
            AppendRow(csv,
            [
                e.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture), e.Category, e.Type, e.Status,
                e.Username, e.RemoteIp, e.Protocol, e.Path, e.TargetPath,
                e.Size?.ToString(CultureInfo.InvariantCulture), e.ElapsedMilliseconds?.ToString(CultureInfo.InvariantCulture),
                e.Actor, e.SessionId, e.Message, e.Details,
            ]);
        }
        return csv.ToString();
    }

    private static void AppendRow(StringBuilder csv, IReadOnlyList<string?> values)
    {
        for (var i = 0; i < values.Count; i++)
        {
            if (i > 0)
                csv.Append(',');
            csv.Append(Escape(values[i]));
        }
        csv.Append("\r\n");
    }

    /// <summary>
    /// Quotes a value when needed. A value that a spreadsheet would run as a formula (=, +, -, @ first) gets a leading
    /// apostrophe: user names and paths come from clients.
    /// </summary>
    private static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;
        if (value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
            value = "'" + value;
        if (value.IndexOfAny([',', '"', '\r', '\n']) < 0)
            return value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}
