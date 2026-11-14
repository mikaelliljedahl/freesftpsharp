using SshServer.Interfaces.Audit;

namespace FreeSftpSharp.Tests.Unit;

public sealed class AuditCsvTests
{
    [Fact]
    public void Writes_a_header_and_quotes_values_with_commas_quotes_and_line_breaks()
    {
        var csv = AuditCsv.Write([new AuditEntry
        {
            TimestampUtc = new DateTime(2026, 11, 14, 8, 30, 0, DateTimeKind.Utc), Category = "File", Type = "Upload", Status = "Ok",
            Username = "alice", Path = "/a, \"b\"\nc.txt", Size = 42,
        }]);

        var lines = csv.Split("\r\n");
        Assert.StartsWith("Timestamp (UTC),Category,Type,Status,Username", lines[0]);
        Assert.StartsWith("2026-11-14 08:30:00.000,File,Upload,Ok,alice,,,\"/a, \"\"b\"\"\nc.txt\",,42,", lines[1]);
    }

    [Theory]
    [InlineData("=HYPERLINK(\"x\")")]
    [InlineData("+1")]
    [InlineData("-1")]
    [InlineData("@SUM(A1)")]
    public void A_value_that_a_spreadsheet_would_run_gets_a_leading_apostrophe(string username)
    {
        var csv = AuditCsv.Write([new AuditEntry { Category = "Auth", Type = "LoginFailed", Status = "Failed", Username = username }]);

        Assert.Contains("'" + username[0], csv.Split("\r\n")[1]);
    }
}
